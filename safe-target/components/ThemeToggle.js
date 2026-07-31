"use client";
import { useEffect, useState } from "react";

// Persists a light/dark UI preference. Only a non-sensitive theme string is
// stored in the browser.
export default function ThemeToggle() {
  const [theme, setTheme] = useState("light");

  useEffect(() => {
    const saved = localStorage.getItem("theme");
    if (saved) setTheme(saved);
  }, []);

  function toggle() {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    localStorage.setItem("theme", next);
  }

  return <button onClick={toggle}>Theme: {theme}</button>;
}
