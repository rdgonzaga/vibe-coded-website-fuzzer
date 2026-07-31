import { menu } from "../../lib/content";

export default function Menu() {
  return (
    <main>
      <h1>Menu</h1>
      {menu.map((group) => (
        <section key={group.category}>
          <h2>{group.category}</h2>
          <ul>
            {group.items.map((item) => (
              <li key={item.name}>
                {item.name} — {item.price}
              </li>
            ))}
          </ul>
        </section>
      ))}
    </main>
  );
}
