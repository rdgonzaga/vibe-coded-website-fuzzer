"use client";

export default function LoginPage() {
  async function handleLogin(email, password) {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    // VULNERABLE: auth token stored in localStorage (readable by any XSS)
    localStorage.setItem("token", data.token);
  }

  return null;
}
