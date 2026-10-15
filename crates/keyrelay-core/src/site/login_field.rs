//! 站点类型的**登录账号约定**（M9-S2 / B-120）。
//!
//! 为什么单独一个模块、而不是塞进 [`super::capability`]：那张表的模块文档把它自己的
//! 用途**锁死在两条**（界面灰显 + 核心层提前拒绝），而且它的字段全是布尔谓词
//! （「支持不支持」）。「登录账号要填邮箱还是用户名」不是能力，是**输入约定**——
//! 两件事、两张表，各有各的冻结测试。
//!
//! 放在同一个目录里的好处一条没丢：两个 `match`（`capabilities()` 与 [`LoginField::of`]）
//! 都是**穷举且无 `_` 臂**的 ⇒ 新增 `SiteKind` 变体时两处都编译不过。
//! 「有登录流程 ⇔ 有账号约定」这条不变量另有测试钉着。
//!
//! # 判据从哪来（真实证据，不是猜的）
//!
//! - **Sub2API 只认邮箱**：本地上游源码 `internal/handler/auth_handler.go:77-83`
//!   —— `Email string` 带 ``binding:"required,email"``；登录服务
//!   `internal/service/auth_service.go:535` 只按邮箱查用户（`userRepo.GetByEmail`），
//!   **没有用户名登录这条路径**。真实站点 `api.example.com` 实测：用户名 `testuser`
//!   → HTTP 400 `Field validation for 'Email' failed on the 'email' tag`（M9-S1 证据 §3）。
//! - **NewAPI 认用户名**：`newapi.example.com` 实测 `testuser` 登录成功（M9-S1 证据 §2）。
//!
//! 纯函数：无 IO、无网络、不读环境变量、不读时钟。

use super::SiteKind;
use crate::error::{Error, Result};

/// 登录时「账号」一栏的输入约定（M9-S2 / B-120）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginField {
    /// 站点用**用户名**登录：本产品**不限制**值形态。
    ///
    /// NewAPI 的 `username` 字段同时接受用户名与邮箱（真实站点用用户名登录成功），
    /// 本产品没有任何依据去限制它。
    Username,
    /// 站点用**邮箱**登录：值必须是邮箱形态。
    Email,
}

impl LoginField {
    /// 站点类型的登录账号约定。`None` = 该类型**没有登录流程**。
    ///
    /// 穷举 `match`、无 `_` 臂：新增 `SiteKind` 变体时这里**编译不过**
    /// （与 `capabilities()` 同一手法）。
    pub fn of(kind: SiteKind) -> Option<Self> {
        match kind {
            // `POST /api/user/login` 收 `username`，用户名/邮箱都行。
            SiteKind::NewApi => Some(LoginField::Username),
            // `POST /api/v1/auth/login` 收 `email`，且带 `binding:"required,email"`。
            SiteKind::Sub2Api => Some(LoginField::Email),
            // 只读兼容端点：没有登录流程（`capabilities().login == false`），
            // 谈不上账号约定。
            SiteKind::CustomOpenAiCompatible => None,
        }
    }

    /// 下发到界面的**稳定取值**。
    ///
    /// 不是给人看的文案：中文文案在页面里（后端给值、前端给词，与 `health` 同一手法），
    /// 这样核心层不必知道界面语言，将来做多语言也不用动这里。
    pub fn as_str(self) -> &'static str {
        match self {
            LoginField::Username => "username",
            LoginField::Email => "email",
        }
    }

    /// 本地预检：这个值**一定**不是该字段能接受的形态 ⇒ 给一句可操作的话。
    ///
    /// # 宁可漏拦，不可误拦
    ///
    /// 误拦会把一次**本来能成功**的登录变成不可能（用户没有任何绕过手段）；
    /// 漏拦只是少省一次往返——而站点原文在 M9-S1 之后已经可见（400 带 `message`）。
    /// 所以这里只拦「任何邮箱语法都不可能出现的形态」，其余一律放行交给站点判。
    pub fn precheck(self, value: &str) -> Result<()> {
        match self {
            LoginField::Username => Ok(()),
            LoginField::Email => {
                if looks_like_email(value) {
                    return Ok(());
                }
                // 文案**不回显**用户输入：用户可能把密码误填进账号栏，而这句话会
                // 出现在界面上（事件表只记 `error_kind`，但界面文案没必要承担这个风险）。
                Err(Error::InvalidInput(
                    "该站点要求用邮箱登录：请把账号填成邮箱地址（形如 name@example.com）；\
                     当前填的不是邮箱形态，站点会直接拒绝"
                        .into(),
                ))
            }
        }
    }
}

/// 「这个值**一定**不是邮箱」的判据。
///
/// 只保留邮箱**必然**满足的性质，刻意**不**做一个校验器：站点侧是
/// go-playground/validator v10.14.0 的 `email` 正则（`regexes.go:18` + `baked_in.go` 的
/// `isEmail`），它比这里**宽**——允许带引号的本地部（`"a@b"@x.com`）、允许引号内的空白、
/// 允许 unicode 域名。本函数若比它严，就会把站点**接受**的输入挡在门外，那是把
/// 「能登录」变成「不能登录」，比少省一次往返严重得多。
///
/// 因此只判这 5 类形态（逐条对应 [`LoginField::precheck`] 文档里的编号）：
///
/// | # | 判据 | 为什么邮箱必然满足 |
/// |---|------|--------------------|
/// | ① | `trim()` 后为空 | 站点 `binding:"required,email"` 的 `required` 先拦空串 |
/// | ② | 整串没有 `@` | 站点正则两侧分支都要求字面量 `@` |
/// | ③ | **原串**以 `@` 开头（本地部零字符） | 本地部至少一个字符 |
/// | ④ | 最后一个 `@` 之后为空 | 域名至少一个字符 |
/// | ⑤ | 域名里没有 `.` | 站点正则域名部分是 `(?:label\.)+tld`，至少一个点 |
///
/// ③ 只查**原串**，不查 trim 后的串（M9-S2 复审 P2-1 的修法）：「本地部零字符」与
/// 「本地部只有空白」是两件事。站点正则的本地部字符类把 `[\x{00A0}-\x{D7FF}]` 整段算
/// 合法，于是 `"\u{a0}@example.com"`（NBSP 当本地部）在站点侧**合法**——若先 trim 掉
/// NBSP 再判「以 `@` 开头」，剩下的 `"@example.com"` 会被当成空本地部而**误拦**一次本来
/// 能成功的登录，而用户没有任何绕过手段。代价是 `"   @example.com"`（前导 ASCII 空白 +
/// 空本地部）改由站点去拒，这按「宁可漏拦」的方向走。修完与真 validator 正则对
/// 46 + 11 个样本逐条比对：误拦 0（证据 §4.1）。
///
/// 刻意不判的：多个 `@`（`"a@b"@x.com` 在站点正则里**合法**）、空白、域名首尾点、
/// 空 label（`a@.com`）、长度上限——多一条规则就多一次误拦的机会。
fn looks_like_email(raw: &str) -> bool {
    // ①：trim 后为空。逻辑上已被 ② 覆盖（空串没有 `@`），显式写出来只为与 spec §4.2
    //    的编号对齐。不可能误拦：全空白的串里不可能有 `@`，也就不可能是邮箱形态。
    if raw.trim().is_empty() {
        return false;
    }
    // ②：整串没有 `@`。分隔符取**最后一个** `@`——带引号的本地部里允许出现 `@`
    // （`"a@b"@x.com`），判「恰好一个 @」会误拦这种站点接受的形态。
    let Some((_, domain)) = raw.rsplit_once('@') else {
        return false;
    };
    // ③ 本地部零字符：判定用**原串**，不用 trim 后的串。站点正则的本地部字符类把
    //    `[\x{00A0}-\x{D7FF}]` 整段算合法 ⇒ NBSP/U+3000 等可以当本地部，先 trim 再判
    //    「以 @ 开头」会把它们误拦掉（详见上方表格 ③ 的说明）。
    // ④ 域名为空（最后一个 `@` 之后什么都没有）。用 `starts_with` 而不是对
    //    `split_once` 取段，理由同 ②。
    if raw.starts_with('@') || domain.is_empty() {
        return false;
    }
    // ⑤ 域名里必须有点。
    domain.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::site::capability::capabilities;

    /// 逐变体写死期望值（**不要**用 `unwrap_or` 之类的写法：那样新增变体时会静默通过）。
    #[test]
    fn login_field_table_is_frozen() {
        assert_eq!(LoginField::of(SiteKind::NewApi), Some(LoginField::Username));
        assert_eq!(LoginField::of(SiteKind::Sub2Api), Some(LoginField::Email));
        assert_eq!(LoginField::of(SiteKind::CustomOpenAiCompatible), None);
    }

    /// **交叉不变量**：有登录流程 ⇔ 有账号约定。
    ///
    /// 把两张表钉在一起：将来给某个类型开/关登录时忘了同步另一张表，这里就红。
    /// 否则会出现两种静默退化——「登录按钮可点，但预检拿不到约定」（永不预检）或
    /// 「没有登录流程却声明了账号形态」（界面给一个永远用不到的标签）。
    #[test]
    fn login_field_agrees_with_the_login_capability() {
        for kind in SiteKind::ALL {
            assert_eq!(
                LoginField::of(kind).is_some(),
                capabilities(kind).login,
                "{}：有登录能力与有账号约定必须一致",
                kind.as_str()
            );
        }
    }

    #[test]
    fn as_str_values_are_stable_and_distinct() {
        assert_eq!(LoginField::Username.as_str(), "username");
        assert_eq!(LoginField::Email.as_str(), "email");
        assert_ne!(LoginField::Username.as_str(), LoginField::Email.as_str());
    }

    /// 判据 ①②④⑤ 里「**一定不是邮箱**」的输入必须被拦下，且文案要指向「邮箱」。
    ///
    /// ③（原串以 `@` 开头）也在里面（`"@qq.com"` / `"@"`）：它同样不可能是邮箱，只是
    /// 判定时**不能**先 trim（见 `looks_like_email` 上方表格 ③ 的说明）。
    #[test]
    fn email_precheck_rejects_only_what_cannot_be_an_email() {
        for bad in [
            "",                   // ① 空串
            "   ",                // ① 空白
            "testuser",           // ② 没有 @（真实站点实测被拒的那个值）
            " testuser ",         // ② trim 之后仍没有 @
            "testuser qq",        // ② 空格不算 @
            "testuser@",          // ④ 域名为空
            "@qq.com",            // ③ 本地部为空
            "@",                  // ③④
            "testuser@qq",        // ⑤ 域名没有点
            "testuser@localhost", // ⑤ 同上（站点正则也要求有点）
        ] {
            let err = LoginField::Email
                .precheck(bad)
                .expect_err("这个值不可能是邮箱，必须本地拦下");
            let text = err.to_string();
            assert!(text.contains("邮箱"), "{bad:?} 的文案要指向邮箱：{text}");
            assert!(matches!(err, Error::InvalidInput(_)), "{bad:?} → {err:?}");
        }
    }

    /// 「刻意不判」清单：这些形态**必须放行**。
    ///
    /// 每一条都对应一次**差点写出来**的误拦；站点可能接受它们，判严了就是把
    /// 「能登录」变成「不能登录」。
    ///
    /// 后面 10 条 Unicode 空白用例是 M9-S2 复审 P2-1 的直接产物：它们都曾被
    /// 「先 `trim()` 再判本地部是否为空」这条实现**误拦**，而真 validator 正则
    /// （`regexes.go` 的本地部字符类含 `[\x{00A0}-\x{D7FF}]`）**收下**它们。
    /// 单独列在这里而不是混在末尾，是为了让「这里每一条都是真出过事的」可读。
    #[test]
    fn email_precheck_accepts_what_the_site_may_accept() {
        for ok in [
            "me@example.com",
            "a@b.c",
            "  me@example.com  ", // trim 后是邮箱（站点会不会拒带空格的，由站点判）
            "\"a@b\"@x.com",      // 带引号的本地部：站点正则明确接受
            "a@b.c.",             // 结尾点：站点正则 `\.?$` 接受
            "a@.com",             // 空 label：站点会拒，但我们不判（少一条规则少一次误拦）
            "a@@b.com",           // 两个 @：由站点判
            "用户@例子.中国",     // unicode：站点正则接受
            "a b@x.com",          // 本地部带空格：站点正则的引号分支允许空白，交站点判
            // ↓ P2-1：本地部**整体是** Unicode 空白。站点收，我们不得拦。
            "\u{a0}@example.com",
            "\u{a0}@b.c",        // NBSP 单字符本地部
            "\u{a0}\u{a0}@b.c",  // 两个 NBSP
            "\u{3000}@x.com",    // 表意空格
            "\u{2000}@b.c",      // en quad
            "\u{2028}@b.c",      // 行分隔符
            "\u{202f}@b.c",      // 窄 NBSP
            "\u{205f}@b.c",      // 数学空格
            "\u{1680}@b.c",      // 欧甘空格
            "\u{a0}@\u{a0}.com", // 域名 label 也是 NBSP：同样不在我们判据内
        ] {
            assert!(
                LoginField::Email.precheck(ok).is_ok(),
                "{ok:?} 必须放行（宁可漏拦不可误拦）"
            );
        }
    }

    /// NewAPI 的 `username` 字段**不做任何形态限制**：真实站点就是用用户名登录的。
    #[test]
    fn username_precheck_never_blocks() {
        for value in [
            "testuser",
            "",
            "   ",
            "用户",
            "me@example.com",
            "@",
            "a b c",
        ] {
            assert!(
                LoginField::Username.precheck(value).is_ok(),
                "{value:?} 不该被拦（NewAPI 的账号栏不限形态）"
            );
        }
    }

    /// P2-1 的**定向回归**：复述旧的（错的）实现，证明新实现与它不同且只在正确的一侧。
    ///
    /// 直接写 `assert_ne!` 没有意义（那只是在测断言本身）；这里把「先 trim 再判空本地部」
    /// 这个具体缺陷重写成一份对照函数，让两件事同时可读：
    /// ① 旧实现确实会把 NBSP 本地部判成 `false`（误拦真的存在过）；
    /// ② 新实现对同一批输入全部放行。
    /// 将来若有人把 `raw.starts_with('@')` 改回 `value.starts_with('@')`，这条会先红。
    #[test]
    fn the_predicate_does_not_treat_a_unicode_whitespace_local_part_as_empty() {
        // 旧的实现（P2-1 中被证伪的那一版），原样搬过来当对照。
        fn old_looks_like_email(raw: &str) -> bool {
            let value = raw.trim();
            let Some((_, domain)) = value.rsplit_once('@') else {
                return false;
            };
            if value.starts_with('@') || domain.is_empty() {
                return false;
            }
            domain.contains('.')
        }

        for local_part in [
            "\u{a0}",
            "\u{a0}\u{a0}",
            "\u{3000}",
            "\u{2000}",
            "\u{2028}",
            "\u{202f}",
            "\u{205f}",
            "\u{1680}",
        ] {
            let value = format!("{local_part}@example.com");
            // ① 旧实现确实误拦——否则这条对照就没有证明力。
            assert!(
                !old_looks_like_email(&value),
                "对照函数应该拦 {value:?}；若它不拦了，说明它已经不是 P2-1 的那一版"
            );
            // ② 新实现必须放行。
            assert!(
                looks_like_email(&value),
                "{value:?} 的本地部是 Unicode 空白，站点正则收，不得误拦"
            );
        }

        // 反向：真正的空本地部仍然要被拒（修 ③ 不能顺手把 ③ 一起废掉）。
        //
        // 注意 `"   @example.com"`（ASCII 空白 + 空本地部）**不在**这个清单里：新实现对
        // 它放行（原串不以 `@` 开头），这是 ③ 改用原串判定的既定代价——交给站点拒。
        // 这些例子上两个实现**行为相同**（差异只发生在「trim 会改动首字符」的输入上），
        // 所以断言的是「相等」，不是「都为真」。
        for value in ["@example.com", "@"] {
            assert!(
                !looks_like_email(value),
                "{value:?} 的本地部是零字符，仍然必须拦"
            );
            assert_eq!(
                old_looks_like_email(value),
                looks_like_email(value),
                "对照函数对 {value:?} 应与新实现一致（这一条不是 P2-1 的差异点）"
            );
        }
    }

    /// 文案**不回显**用户输入。
    ///
    /// 用户完全可能把密码填进账号栏（M8 的 `special_character_passwords_reach_no_outlet`
    /// 就是这一类）；这句话会出现在界面上，没必要把一个可能是密码的串再抄一遍。
    #[test]
    fn the_rejection_message_does_not_echo_the_input() {
        let err = LoginField::Email.precheck("hunter2-hunter2").unwrap_err();
        let text = err.to_string();
        assert!(!text.contains("hunter2"), "错误文案回显了用户输入：{text}");
        assert!(text.contains("邮箱"), "{text}");
    }
}
