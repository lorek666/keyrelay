//! M43-S2：**成本估算的纯函数**（无 IO、无线程、无时钟）。
//!
//! 单独成模块的理由：它要被「Usage 页的日聚合」「按 agent 成本」「测试」三处共用。
//! 把「取哪一版价格」与「怎么算 / 怎么舍入」分开，才能对**生效时间**与**舍入**各写一条
//! 能变红的单测（spec §4.2 / §4.6）。
//!
//! **红线**：没有价格 ⇒ `None`（未知），**绝不**回退成 `0.0`。

/// 一个价格版本（`store::ModelPriceRow` 的纯数据投影）。
#[derive(Clone, Debug, PartialEq)]
pub struct PricePoint {
    /// 每 1M input token 的价格（> 0；写入时已校验）
    pub input_per_mtok: f64,
    /// 每 1M output token 的价格（> 0）
    pub output_per_mtok: f64,
    /// `"USD"` | `"CNY"`（写入时已校验）
    pub currency: String,
    /// 生效时间（unix 秒）
    pub effective_from: i64,
}

/// 四舍五入（**half-up**，不是银行家舍入），保留 `digits` 位小数。
///
/// 为什么不用 `f64::round`：它只到整数位；为什么不用格式化：那会引入字符串分配且
/// 不同格式化器的舍入模式不一致（`{:.6}` 在 .5 边界上不是 half-up）。
pub fn round_half_up(x: f64, digits: u32) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let scale = 10f64.powi(digits as i32);
    if x >= 0.0 {
        (x * scale + 0.5).floor() / scale
    } else {
        -(((-x) * scale + 0.5).floor() / scale)
    }
}

/// 从**同一 model + currency** 的价格序列里取「**不晚于** `at` 的最新一版」。
///
/// - `at <= 0`（M40-S1 之前的旧行）⇒ `None`：没有生效时间可对，任何价格都不适用；
/// - 空序列 ⇒ `None`（未知）。
pub fn price_at(points: &[PricePoint], at: i64) -> Option<&PricePoint> {
    if at <= 0 {
        return None;
    }
    points
        .iter()
        .filter(|p| p.effective_from <= at)
        .max_by_key(|p| p.effective_from)
}

/// 一条用量的估算成本。
///
/// 计算在 f64 里做、**中间不四舍五入**，只在返回前 `round_half_up(x, 6)`（spec §4.6）。
/// `price = None` ⇒ `None`（未知）。负 token 视作 0（防御；M40 的账本本不该出现负数）。
pub fn estimate_cost(
    prompt_tokens: i64,
    completion_tokens: i64,
    price: Option<&PricePoint>,
) -> Option<f64> {
    let price = price?;
    let prompt = prompt_tokens.max(0) as f64;
    let completion = completion_tokens.max(0) as f64;
    let raw = prompt / 1_000_000.0 * price.input_per_mtok
        + completion / 1_000_000.0 * price.output_per_mtok;
    Some(round_half_up(raw, 6))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(input: f64, output: f64, currency: &str, from: i64) -> PricePoint {
        PricePoint {
            input_per_mtok: input,
            output_per_mtok: output,
            currency: currency.to_string(),
            effective_from: from,
        }
    }

    #[test]
    fn rounding_is_half_up_to_six_places() {
        assert_eq!(round_half_up(0.0000005, 6), 0.000001);
        assert_eq!(round_half_up(0.0000004, 6), 0.0);
        assert_eq!(round_half_up(1.2345675, 6), 1.234568);
        assert_eq!(round_half_up(2.5, 0), 3.0, "half-up 不是银行家舍入");
        assert_eq!(round_half_up(3.5, 0), 4.0);
        assert_eq!(round_half_up(-2.5, 0), -3.0, "负数对称");
        assert!(round_half_up(f64::NAN, 6).is_nan());
        assert_eq!(round_half_up(f64::INFINITY, 6), f64::INFINITY);
    }

    #[test]
    fn price_at_picks_the_latest_version_not_after_at() {
        let prices = vec![point(1.0, 2.0, "USD", 1_000), point(3.0, 4.0, "USD", 2_000)];
        assert_eq!(price_at(&prices, 999).map(|p| p.input_per_mtok), None);
        assert_eq!(
            price_at(&prices, 1_000).map(|p| p.input_per_mtok),
            Some(1.0),
            "边界含"
        );
        assert_eq!(
            price_at(&prices, 1_999).map(|p| p.input_per_mtok),
            Some(1.0)
        );
        assert_eq!(
            price_at(&prices, 2_000).map(|p| p.input_per_mtok),
            Some(3.0)
        );
        assert_eq!(
            price_at(&prices, 9_999).map(|p| p.input_per_mtok),
            Some(3.0)
        );
        // 旧行（M40 之前）不可定价
        assert!(price_at(&prices, 0).is_none());
        assert!(price_at(&prices, -5).is_none());
        // 空序列
        assert!(price_at(&[], 1_000).is_none());
    }

    #[test]
    fn estimate_cost_is_none_when_no_price_applies() {
        assert!(
            estimate_cost(1_000, 1_000, None).is_none(),
            "无价格 ⇒ 未知，不是 0"
        );
        let p = point(2.0, 8.0, "USD", 1);
        // 1M prompt + 0.5M completion = 2.0 + 4.0 = 6.0
        assert_eq!(estimate_cost(1_000_000, 500_000, Some(&p)), Some(6.0));
        // 负 token 视作 0（防御）
        assert_eq!(estimate_cost(-100, 0, Some(&p)), Some(0.0));
        // 6 位精度的边界：1 token × 1.0/1M = 1e-6（恰好可表示）
        let unit = point(1.0, 1.0, "USD", 1);
        assert_eq!(estimate_cost(1, 0, Some(&unit)), Some(0.000001));
        // 低于 6 位精度的成本四舍五入为 0.0 —— 这是**有价格**的 0（与「未知」不同），
        // 展示层按 §4.6 显示「<0.0001」，不得把它当作「免费」。
        let tiny = point(0.0000001, 0.0000001, "USD", 1);
        assert_eq!(estimate_cost(1, 1, Some(&tiny)), Some(0.0));
    }

    #[test]
    fn estimate_cost_never_returns_zero_for_unpriced_rows() {
        // 价格缺失与「价格存在但算出 0」必须可区分：前者 None，后者 Some(0.0)。
        let zero_price = point(0.0, 0.0, "USD", 1);
        assert_eq!(estimate_cost(0, 0, Some(&zero_price)), Some(0.0));
        assert!(estimate_cost(0, 0, None).is_none());
    }
}
