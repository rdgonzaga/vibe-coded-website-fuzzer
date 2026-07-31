import { hours, featured } from "../lib/content";

export default function Home() {
  return (
    <main>
      <h1>Brew &amp; Bytes Cafe</h1>
      <p>A cozy neighborhood cafe serving specialty coffee and fresh pastries.</p>

      <h2>Today&apos;s Featured Drinks</h2>
      <ul>
        {featured.map((item) => (
          <li key={item.name}>
            {item.name} — {item.description}
          </li>
        ))}
      </ul>

      <h2>Opening Hours</h2>
      <ul>
        {hours.map((row) => (
          <li key={row.day}>
            {row.day}: {row.open} to {row.close}
          </li>
        ))}
      </ul>
    </main>
  );
}
