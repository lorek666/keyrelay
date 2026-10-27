export default function BrandMark({ size = 36 }: { size?: number }) {
  return (
    <svg
      className="brand-mark"
      width={size}
      height={size}
      viewBox="0 0 40 40"
      fill="none"
      aria-hidden="true"
    >
      <rect width="40" height="40" rx="12" fill="currentColor" />
      <path
        d="M12 14.5 20 10l8 4.5v11L20 30l-8-4.5v-11Z"
        stroke="white"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
      <path
        d="m12 14.5 8 4.6 8-4.6M20 19v11M16 12.2l8 4.6v4.6l-8-4.6v-4.6Z"
        stroke="white"
        strokeWidth="1.7"
        strokeLinejoin="round"
      />
    </svg>
  );
}
