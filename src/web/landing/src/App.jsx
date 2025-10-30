import { useEffect, useMemo, useState, createContext, useContext } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck, Cpu, Database, GitFork, Gauge, Lock, Github, Download,
  ChevronRight, Workflow, Layers, BarChart3, Zap, FileSearch, LogOut
} from "lucide-react";
import { signIn, signUp, signOut, getCurrentUser, upgradeUserPlan } from "./api";

function Container({ className = "", children }) {
  return <div className={`mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 ${className}`}>{children}</div>;
}
function Button({ as: Comp = "button", className = "", children, ...props }) {
  return (
    <Comp
      className={`inline-flex items-center gap-2 rounded-2xl px-5 py-3 text-sm font-semibold shadow-sm transition focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 ${className}`}
      {...props}
    >
      {children}
    </Comp>
  );
}
function Badge({ children }) {
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-medium text-white/90 backdrop-blur">
      {children}
    </span>
  );
}
function Card({ className = "", children }) {
  return (
    <div className={`rounded-3xl border border-white/10 bg-white/[0.03] p-6 shadow-[0_0_1px_1px_rgba(255,255,255,0.04)_inset] backdrop-blur ${className}`}>
      {children}
    </div>
  );
}

// ---------- Auth Context ----------
const AuthCtx = createContext(null);
function useAuth() { return useContext(AuthCtx); }
function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [plan, setPlan] = useState("free");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const { user, plan } = await getCurrentUser();
      setUser(user);
      if (plan) setPlan(plan);
      setLoading(false);
    })();
  }, []);

  const value = useMemo(() => ({ user, setUser, plan, setPlan, loading }), [user, plan, loading]);
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

// ---------- Auth Modal ----------
function AuthModal({ open, mode = "signin", onClose }) {
  const { setUser, setPlan } = useAuth();
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");

  useEffect(() => { if (open) { setError(""); setInfo(""); setPending(false); } }, [open, mode]);
  if (!open) return null;

  async function handleSubmit(e) {
    e.preventDefault();
    setPending(true);
    setError("");
    setInfo("");

    const fn = mode === "signup" ? signUp : signIn;
    const res = await fn(form);
    setPending(false);

    if (res?.pendingConfirmation) {
      setInfo(res.message || "Check your email to confirm your account.");
      return;
    }
    if (res?.error) {
      setError(res.error);
      return;
    }
    if (res?.user) setUser(res.user);
    if (res?.plan) setPlan(res.plan);
    onClose?.();
  }

  return (
    <div className="fixed inset-0 z-[200] bg-black/60 backdrop-blur-sm grid place-items-center p-4">
      <Card className="w-full max-w-md">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold">{mode === "signup" ? "Create your account" : "Sign in to CryptoScope"}</h3>
          <button onClick={onClose} className="text-white/60 hover:text-white">✕</button>
        </div>
        <form className="mt-4 space-y-3" onSubmit={handleSubmit}>
          {mode === "signup" && (
            <div>
              <label className="text-sm text-white/70">Name</label>
              <input
                className="mt-1 w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 outline-none focus:ring-2"
                placeholder="Ada Lovelace"
                value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                required
              />
            </div>
          )}
          <div>
            <label className="text-sm text-white/70">Email</label>
            <input
              type="email"
              className="mt-1 w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 outline-none focus:ring-2"
              placeholder="you@example.com"
              value={form.email}
              onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              required
            />
          </div>
          <div>
            <label className="text-sm text-white/70">Password</label>
            <input
              type="password"
              className="mt-1 w-full rounded-xl border border-white/10 bg-white/5 px-3 py-2 outline-none focus:ring-2"
              placeholder="••••••••"
              value={form.password}
              onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              required
            />
          </div>
          {error && <div className="text-sm text-rose-400">{String(error)}</div>}
          {info && <div className="text-sm text-emerald-400">{String(info)}</div>}
          <Button disabled={pending} className="w-full justify-center bg-gradient-to-r from-emerald-400 to-cyan-500 text-black">
            {pending ? "Please wait…" : (mode === "signup" ? "Create account" : "Sign in")}
          </Button>
        </form>
        <div className="mt-4 text-center text-sm text-white/70">
          {mode === "signup" ? (
            <>Already have an account?{" "}
              <button className="underline underline-offset-4 hover:text-white" onClick={() => window.dispatchEvent(new CustomEvent("auth:switch", { detail: "signin" }))}>
                Sign in
              </button></>
          ) : (
            <>No account?{" "}
              <button className="underline underline-offset-4 hover:text-white" onClick={() => window.dispatchEvent(new CustomEvent("auth:switch", { detail: "signup" }))}>
                Create one
              </button></>
          )}
        </div>
      </Card>
    </div>
  );
}

// ---------- Nav ----------
function Nav({ onOpenAuth }) {
  const [open, setOpen] = useState(false);
  const { user, plan, setUser, setPlan } = useAuth();

  async function handleSignOut() {
    await signOut();
    setUser(null);
    setPlan("free");
  }

  return (
    <header className="sticky top-0 z-50 border-b border-white/10 backdrop-blur bg-black/40">
      <Container className="flex items-center justify-between py-4">
        <a href="#" className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500" />
          <span className="text-lg font-semibold tracking-tight">CryptoScope</span>
        </a>
        <nav className="hidden md:flex items-center gap-8 text-sm text-white/80">
          <a href="#features" className="hover:text-white">Features</a>
          <a href="#how-it-works" className="hover:text-white">Pipeline</a>
          <a href="#pricing" className="hover:text-white">Pricing</a>
          <a href="#faq" className="hover:text-white">FAQ</a>
        </nav>
        <div className="hidden md:flex items-center gap-3">
          {!user ? (
            <>
              <Button onClick={() => onOpenAuth("signin")} className="border border-white/15 text-white/90 hover:bg-white/5">Sign in</Button>
              <Button onClick={() => onOpenAuth("signup")} className="bg-gradient-to-r from-emerald-400 to-cyan-500 text-black">
                Sign up <ChevronRight className="h-4 w-4" />
              </Button>
            </>
          ) : (
            <>
              <Badge>{plan === "premium" ? "Premium" : "Free"}</Badge>
              <Button className="border border-white/15 text-white/90 hover:bg-white/5" onClick={handleSignOut}>
                <LogOut className="h-4 w-4" /> Sign out
              </Button>
            </>
          )}
        </div>
        <button className="md:hidden" onClick={() => setOpen(!open)} aria-label="Open menu">
          <div className="h-6 w-6 rounded-md border border-white/20 grid place-content-center text-white/80">≡</div>
        </button>
      </Container>
      {open && (
        <div className="md:hidden border-t border-white/10 bg-black/60">
          <Container className="flex flex-col gap-3 py-4 text-sm">
            <a href="#features" className="text-white/80 hover:text-white">Features</a>
            <a href="#how-it-works" className="text-white/80 hover:text-white">Pipeline</a>
            <a href="#pricing" className="text-white/80 hover:text-white">Pricing</a>
            <a href="#faq" className="text-white/80 hover:text-white">FAQ</a>
            <div className="pt-2 flex gap-3">
              {!user ? (
                <>
                  <Button onClick={() => onOpenAuth("signin")} className="border border-white/15 text-white/90 hover:bg-white/5 w-full justify-center">Sign in</Button>
                  <Button onClick={() => onOpenAuth("signup")} className="bg-gradient-to-r from-emerald-400 to-cyan-500 text-black w-full justify-center">
                    Sign up <ChevronRight className="h-4 w-4" />
                  </Button>
                </>
              ) : (
                <>
                  <Badge>{plan === "premium" ? "Premium" : "Free"}</Badge>
                  <Button className="border border-white/15 text-white/90 hover:bg-white/5 w-full justify-center" onClick={() => { setOpen(false); }}>
                    Continue
                  </Button>
                </>
              )}
            </div>
          </Container>
        </div>
      )}
    </header>
  );
}

// ---------- Hero (unchanged, no Live Demo) ----------
function Hero() { /* … keep your existing Hero from earlier message … */ return (
  <section className="relative overflow-hidden">
    <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(ellipse_at_top,rgba(16,185,129,0.25),transparent_50%),radial-gradient(ellipse_at_bottom,rgba(34,211,238,0.18),transparent_55%)]" />
    <Container className="grid items-center gap-10 py-20 lg:grid-cols-2">
      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6 }} className="space-y-6">
        <Badge><ShieldCheck className="h-4 w-4" /> Crypto analysis for modern blockchain systems</Badge>
        <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold leading-tight">
          Detect &amp; Understand <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">Cryptographic Functions</span> fast.
        </h1>
        <p className="text-white/70 text-base sm:text-lg max-w-xl">
          Purpose-built for auditors: CryptoScope maps cryptographic usage across codebases and binaries, highlights weak/legacy algorithms, and provides NIST-informed scoring so you can justify findings and remediation with evidence.
        </p>

        <div className="flex flex-wrap gap-3 pt-2">
          <Button as="a" href="#get-started" className="bg-gradient-to-r from-emerald-400 to-cyan-500 text-black">
            <Download className="h-4 w-4" /> Download (Desktop)
          </Button>
          <Button as="a" href="#github" className="border border-white/15 text-white/90 hover:bg-white/5">
            <Github className="h-4 w-4" /> GitHub
          </Button>
        </div>
        <ul className="mt-6 grid max-w-xl grid-cols-2 gap-3 text-sm text-white/60">
          <li className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-400"/> NIST-informed scoring</li>
          <li className="flex items-center gap-2"><Zap className="h-4 w-4 text-cyan-400"/> Fast static &amp; optional dynamic analysis</li>
          <li className="flex items-center gap-2"><Lock className="h-4 w-4 text-emerald-400"/> Offline desktop mode</li>
          <li className="flex items-center gap-2"><Database className="h-4 w-4 text-cyan-400"/> JSON/NDJSON exports</li>
        </ul>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.6, delay: 0.1 }} className="relative">
        <div className="absolute -inset-6 rounded-3xl bg-gradient-to-br from-emerald-500/10 via-transparent to-cyan-500/10 blur-2xl" />
        <Card className="relative p-0 overflow-hidden">
          <div className="flex items-start justify-between p-6">
            <div className="flex items-center gap-2 text-xs text-white/60">
              <span className="h-3 w-3 rounded-full bg-rose-400" />
              <span className="h-3 w-3 rounded-full bg-amber-400" />
              <span className="h-3 w-3 rounded-full bg-emerald-400" />
              <span className="ml-2">analysis.ndjson</span>
            </div>
            <Badge>Preview</Badge>
          </div>
          <pre className="px-6 pb-6 text-xs sm:text-sm leading-relaxed text-white/80">{`{"file":"/build/wallet.exe","matches":[
  {"algo":"SHA-256","type":"hash","confidence":0.98,"line":214},
  {"algo":"AES-256-GCM","type":"cipher","confidence":0.94,"line":377},
  {"algo":"RIPEMD-160","type":"hash","confidence":0.72,"line":502}
],"score":{"security":0.88,"performance":0.76,"adoption":0.91}}`}</pre>
        </Card>
      </motion.div>
    </Container>
  </section>
);}

const features = [
  {
    icon: <FileSearch className="h-5 w-5" />,
    title: "Audit-grade discovery",
    desc: "Identify hashes, ciphers, KDFs and protocols across source, repos, and compiled artifacts."
  },
  {
    icon: <Cpu className="h-5 w-5" />,
    title: "Static + runtime hints",
    desc: "Signature rules and AST analysis with optional Frida hooks for runtime confirmation."
  },
  {
    icon: <Gauge className="h-5 w-5" />,
    title: "Fast evidence collection",
    desc: "Parallel scans with cached results for repeatable, diffable audit runs."
  },
  {
    icon: <ShieldCheck className="h-5 w-5" />,
    title: "NIST-informed scoring",
    desc: "Rank algorithms by strength, performance, and adoption to prioritize risk."
  },
  {
    icon: <Database className="h-5 w-5" />,
    title: "Defensible reports",
    desc: "Export JSON/NDJSON with locations, confidence, and context for your workpapers."
  },
  {
    icon: <Layers className="h-5 w-5" />,
    title: "Fits audit workflows",
    desc: "CLI/CI integration, role-appropriate outputs, and reproducible pipelines."
  },
];
function Features(){ /* unchanged */ return (
  <section id="features" className="py-20">
    <Container>
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="text-3xl sm:text-4xl font-semibold">Built for auditors & secure teams</h2>
        <p className="mt-3 text-white/70">Actionable detections, rich context, and exports that play nicely with the rest of your toolchain.</p>
      </div>
      <div className="mt-10 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {features.map((f, i) => (
          <motion.div key={i} initial={{ opacity: 0, y: 10 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.4, delay: i * 0.05 }}>
            <Card className="h-full">
              <div className="flex items-center gap-3 text-emerald-300">
                <div className="grid h-9 w-9 place-content-center rounded-xl bg-emerald-500/10 border border-emerald-400/20 text-emerald-300">{f.icon}</div>
                <h3 className="text-base font-semibold text-white">{f.title}</h3>
              </div>
              <p className="mt-3 text-sm text-white/70">{f.desc}</p>
            </Card>
          </motion.div>
        ))}
      </div>
    </Container>
  </section>
);}
function HowItWorks(){ /* unchanged */ return (
  <section id="how-it-works" className="py-20">
    <Container>
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="text-3xl sm:text-4xl font-semibold">Pipeline at a glance</h2>
        <p className="mt-3 text-white/70">Designed for repeatable, diffable audits that map to compliance frameworks.</p>
      </div>
      <div className="mt-12 grid gap-6 lg:grid-cols-4 sm:grid-cols-2">
        {[
          { icon: <GitFork className="h-5 w-5" />, title: "Ingest", desc: "Drop files, point to a repo, or attach build artifacts." },
          { icon: <Cpu className="h-5 w-5" />, title: "Analyze", desc: "Static rules + AST + optional Frida hooks for runtime hints." },
          { icon: <BarChart3 className="h-5 w-5" />, title: "Score", desc: "NIST-based weights and adoption metrics produce a clear ranking." },
          { icon: <Workflow className="h-5 w-5" />, title: "Report", desc: "Export NDJSON/JSON; diff audits over time; share in CI or PDFs." },
        ].map((s, i) => (
          <Card key={i} className="relative">
            <div className="flex items-center gap-3">
              <div className="grid h-9 w-9 place-content-center rounded-xl bg-cyan-500/10 border border-cyan-400/20 text-cyan-300">{s.icon}</div>
              <h3 className="font-semibold">{s.title}</h3>
            </div>
            <p className="mt-3 text-sm text-white/70">{s.desc}</p>
            {i < 3 && <div className="absolute -right-3 top-1/2 hidden translate-y-[-50%] lg:block"><ChevronRight className="h-6 w-6 text-white/30" /></div>}
          </Card>
        ))}
      </div>
    </Container>
  </section>
);}
function Pricing({ onRequireAuth }) {
  const { user, plan, setPlan } = useAuth();

  async function handleSelect(planName) {
    if (!user) return onRequireAuth?.("signin");
    const { error, plan: newPlan } = await upgradeUserPlan({ userId: user.id, plan: planName });
    if (error) return alert("Upgrade failed: " + error);
    setPlan(newPlan || planName);
    alert("You're now on " + (newPlan || planName) + " 🎉");
  }

  const cards = [
    {
      name: "Free",
      price: "$0",
      tagline: "For quick checks & students",
      cta: plan === "free" ? "Current plan" : "Start Free",
      features: ["Single-file scans", "Core ruleset", "JSON export"],
    },
    {
      name: "Premium",
      price: "$19/mo",
      tagline: "For professional audits",
      cta: plan === "premium" ? "Current plan" : "Go Premium",
      featured: true,
      features: ["Multi-file & repo scanning", "NDJSON streaming", "Diffable audit history", "Optional dynamic hooks"],
    },
  ];

  return (
    <section id="pricing" className="py-20">
      <Container>
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl sm:text-4xl font-semibold">Simple, transparent pricing</h2>
          <p className="mt-3 text-white/70">Choose a plan that matches your audit workflow. Upgrade anytime.</p>
        </div>

        {/* Centered 2-col grid, equal-height cards */}
        <div className="mt-10 grid gap-6 sm:grid-cols-2 max-w-4xl mx-auto items-stretch">
          {cards.map((p, i) => (
            <Card
              key={i}
              className={`h-full flex flex-col ${p.featured ? "border-emerald-400/30 bg-emerald-400/5" : ""}`}
            >
              <div className="flex items-baseline justify-between">
                <h3 className="text-xl font-semibold">{p.name}</h3>
                <Badge>{p.tagline}</Badge>
              </div>

              <div className="mt-4 text-4xl font-bold">{p.price}</div>

              <ul className="mt-6 space-y-2 text-sm text-white/80">
                {p.features.map((f, idx) => (
                  <li key={idx} className="flex items-center gap-2">
                    <div className="h-5 w-5 rounded-md border border-white/15 bg-white/5 grid place-content-center">
                      <span className="text-emerald-300">✓</span>
                    </div>
                    {f}
                  </li>
                ))}
              </ul>

              {/* push CTA to bottom for equal alignment */}
              <div className="flex-1" />

              {p.name === "Premium" ? (
                <Button
                  onClick={() => handleSelect("premium")}
                  className={`mt-6 w-full justify-center ${
                    p.featured
                      ? "bg-gradient-to-r from-emerald-400 to-cyan-500 text-black"
                      : "border border-white/15 text-white/90 hover:bg-white/5"
                  }`}
                >
                  {p.cta}
                </Button>
              ) : (
                <Button
                  onClick={() => (user ? alert("You're on Free.") : onRequireAuth?.("signup"))}
                  className="mt-6 w-full justify-center border border-white/15 text-white/90 hover:bg-white/5"
                >
                  {p.cta}
                </Button>
              )}
            </Card>
          ))}
        </div>
      </Container>
    </section>
  );
}

function FAQ(){ /* unchanged */ return (
  <section id="faq" className="py-20">
    <Container>
      <div className="mx-auto max-w-2xl text-center">
        <h2 className="text-3xl sm:text-4xl font-semibold">Frequently asked questions</h2>
        <p className="mt-3 text-white/70">Don’t see your question? Reach out and we’ll help you evaluate the fit.</p>
      </div>
      <div className="mx-auto mt-10 max-w-3xl divide-y divide-white/10 rounded-2xl border border-white/10 bg-white/[0.03]">
        {[
          { q: "What platforms are supported?", a: "Windows for the desktop app"},
          { q: "Which languages/targets can you scan?", a: "Start with EVM/solidity sources and bytecode, common C/C++/Rust/Go/JS repos, and generic binaries. More to come." },
          { q: "How do exports work?", a: "Use JSON for single reports or NDJSON for streaming line-by-line detections." },
          { q: "Does it work offline?", a: "Yes. Premium and Admin tiers support full offline scanning with local rule packs." },
        ].map((f, i) => (
          <details key={i} className="group">
            <summary className="flex cursor-pointer list-none items-center justify-between px-6 py-4 text-left text-white/90">
              <span className="font-medium">{f.q}</span>
              <ChevronRight className="h-4 w-4 transition group-open:rotate-90 text-white/50" />
            </summary>
            <div className="px-6 pb-6 text-sm text-white/70">{f.a}</div>
          </details>
        ))}
      </div>
    </Container>
  </section>
);}
function Footer(){ return (
  <footer className="border-t border-white/10 py-10">
    <Container className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
      <div className="flex items-center gap-3">
        <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500" />
        <span className="text-white/80">© {new Date().getFullYear()} CryptoScope</span>
      </div>
      <div className="flex gap-6 text-sm text-white/70">
        <a href="#privacy" className="hover:text-white">Privacy</a>
        <a href="#terms" className="hover:text-white">Terms</a>
        <a href="#security" className="hover:text-white">Security</a>
      </div>
    </Container>
  </footer>
);}

export default function CryptoScopeLanding() {
  const [authOpen, setAuthOpen] = useState(false);
  const [authMode, setAuthMode] = useState("signin");

  useEffect(() => {
    const onSwitch = (e) => setAuthMode(e.detail === "signup" ? "signup" : "signin");
    window.addEventListener("auth:switch", onSwitch);
    return () => window.removeEventListener("auth:switch", onSwitch);
  }, []);

  function openAuth(mode = "signin") { setAuthMode(mode); setAuthOpen(true); }

  return (
    <AuthProvider>
      <div className="min-h-screen bg-black text-white">
        <Nav onOpenAuth={openAuth} />
        <Hero />
        <Features />
        <HowItWorks />
        <Pricing onRequireAuth={openAuth} />
        <FAQ />
        <Footer />
        <AuthModal open={authOpen} mode={authMode} onClose={() => setAuthOpen(false)} />
      </div>
    </AuthProvider>
  );
}
