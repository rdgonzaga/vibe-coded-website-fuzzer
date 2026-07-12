"use client";

// app/profile/page.js
//
// ⚠️ INTENTIONALLY VULNERABLE — TRAINING/TESTING USE ONLY ⚠️
//
// This page just reflects whatever ?id= is in the URL to the vulnerable
// /api/profile/[id] endpoint, so changing the id in the address bar (e.g.
// /profile?id=2) while logged in as a different user demonstrates the
// IDOR / broken access control bug server-side.

import { Suspense, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";

function ProfileInner() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id");
  const [profile, setProfile] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!id) return;
    const token = typeof window !== "undefined" ? localStorage.getItem("token") : null;

    fetch(`/api/profile/${id}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to load profile");
        setProfile(data.user);
      })
      .catch((e) => setError(e.message));
  }, [id]);

  return (
    <>
      {error && <p style={{ color: "red" }}>{error}</p>}
      {profile && (
        <pre style={{ background: "#f4f4f4", padding: 16 }}>
          {JSON.stringify(profile, null, 2)}
        </pre>
      )}
    </>
  );
}

export default function ProfilePage() {
  return (
    <main style={{ maxWidth: 480, margin: "80px auto", fontFamily: "sans-serif" }}>
      <h1>Profile</h1>
      <p style={{ fontSize: 12, color: "#b00" }}>
        Try changing the id in the URL (?id=1, ?id=2, ?id=3) while logged in as
        someone else — the API doesn&apos;t check ownership.
      </p>
      <Suspense fallback={<p>Loading...</p>}>
        <ProfileInner />
      </Suspense>
      <p>
        <a href="/products">Browse products →</a>
      </p>
    </main>
  );
}
