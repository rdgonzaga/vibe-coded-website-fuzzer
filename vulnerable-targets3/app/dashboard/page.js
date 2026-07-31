"use client";

export default function Dashboard() {
  function saveSession(data) {
    // VULNERABLE: JWT kept in sessionStorage, exposed to any XSS on the page
    sessionStorage.setItem("authToken", data.jwt);
  }

  return null;
}
