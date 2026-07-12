"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

export default function Navbar() {
  const [user, setUser] = useState(null);
  const router = useRouter();

  useEffect(() => {
    try {
      const raw = localStorage.getItem("user");
      if (raw) setUser(JSON.parse(raw));
    } catch {
      setUser(null);
    }
  }, []);

  function handleLogout() {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setUser(null);
    router.push("/");
  }

  return (
    <header className="navbar">
      <div className="navbar-inner">
        <a href="/" className="navbar-brand">
          🛒 Vuln-Shop
        </a>
        <nav className="navbar-links">
          <a href="/products">Products</a>
          {user ? (
            <>
              <a href={`/profile?id=${user.id}`}>{user.name || user.email}</a>
              <button className="navbar-link-btn" onClick={handleLogout}>
                Log out
              </button>
            </>
          ) : (
            <>
              <a href="/login">Login</a>
              <a href="/register">Register</a>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}
