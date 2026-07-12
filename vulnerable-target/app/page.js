// app/page.js
export default function Home() {
  return (
    <>
      <section className="hero">
        <span className="badge">Security training demo</span>
        <h1>🛒 Vuln-Shop</h1>
        <p>
          A deliberately vulnerable Next.js e-commerce demo for security
          training/testing only. Do not deploy this publicly or reuse this code.
          See <code>README.md</code> for the full list of intentional bugs.
        </p>
      </section>

      <div className="page page-wide" style={{ marginTop: 0 }}>
        <div className="nav-grid">
          <a href="/login" className="nav-card">
            <div className="nav-card-icon">🔑</div>
            <div className="nav-card-title">Login</div>
            <div className="nav-card-desc">Sign in with a demo account</div>
          </a>
          <a href="/register" className="nav-card">
            <div className="nav-card-icon">📝</div>
            <div className="nav-card-title">Register</div>
            <div className="nav-card-desc">Create a new account</div>
          </a>
          <a href="/products" className="nav-card">
            <div className="nav-card-icon">🛍️</div>
            <div className="nav-card-title">Products</div>
            <div className="nav-card-desc">SQL injection demo</div>
          </a>
          <a href="/profile?id=1" className="nav-card">
            <div className="nav-card-icon">👤</div>
            <div className="nav-card-title">Profile</div>
            <div className="nav-card-desc">IDOR demo</div>
          </a>
        </div>
      </div>
    </>
  );
}
