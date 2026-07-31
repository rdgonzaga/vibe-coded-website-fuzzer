// Small display helpers. Pure functions, no I/O, no secrets.

export function formatPrice(cents) {
  return "$" + (cents / 100).toFixed(2);
}

export function formatDay(date) {
  return new Intl.DateTimeFormat("en-US", { weekday: "long" }).format(date);
}
