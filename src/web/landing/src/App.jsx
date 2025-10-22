import { useState } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  Cpu,
  Database,
  GitFork,
  Gauge,
  Lock,
  Github,
  Download,
  Sparkles,
  ChevronRight,
  Workflow,
  Layers,
  BarChart3,
  Zap,
  FileSearch,
} from "lucide-react";

function Container({ className = "", children }) {
  return (
    <div className={`mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 ${className}`}>
      {children}
    </div>
  );
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

function Nav() {
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-50 border-b border-white/10 backdrop-blur bg-black/40">
      <Container className="flex items-center justify-between py-4">
        <a href="#" className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-emerald-400 to-cyan-500" />
          <span className="text-lg font-semibold tracking-tight">
            CryptoScope
          </span>
        </a>
        <nav className="hidden md:flex items-center gap-8 text-sm text-white/80">
          <a href="#features" className="hover:text-white">Features</a>
          <a href="#how-it-works" className="hover:text-white">Pipeline</a>
          <a href="#pricing" className="hover:text-white">Pricing</a>
          <a href="#faq" className="hover:text-white">FAQ</a>
        </nav>
        <div className="hidden md:flex items-center gap-3">
          <Button as="a" href="#demo" className="border border-white/15 text-white/90 hover:bg-white/5">
            <Sparkles className="h-4 w-4" /> Live Demo
          </Button>
          <Button
            as="a"
            href="#get-started"
            className="bg-gradient-to-r from-emerald-400 to-cyan-500 text-black hover:opacity-90"
          >
            Get Started <ChevronRight className="h-4 w-4" />
          </Button>
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
              <Button as="a" href="#demo" className="border border-white/15 text-white/90 hover:bg:white/5 w-full justify-center">
                <Sparkles className="h-4 w-4" /> Live Demo
              </Button>
              <Button as="a" href="#get-started" className="bg-gradient-to-r from-emerald-400 to-cyan-500 text-black w-full justify-center">
                Get Started <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </Container>
        </div>
      )}
    </header>
  );
}

function Hero() {
  return (
    <section className="relative overflow-hidden">
      <div className="pointer-events-none absolute inset-0 -z-10 bg-[radial-gradient(ellipse_at_top,rgba(16,185,129,0.25),transparent_50%),radial-gradient(ellipse_at_bottom,rgba(34,211,238,0.18),transparent_55%)]" />
      <Container className="grid items-center gap-10 py-20 lg:grid-cols-2">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="space-y-6"
        >
          <Badge>
            <ShieldCheck className="h-4 w-4" /> Crypto analysis for modern blockchain systems
          </Badge>
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-semibold leading-tight">
            Detect &amp; Understand <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">Cryptographic Functions</span> fast.
          </h1>
          <p className="text-white/70 text-base sm:text-lg max-w-xl">
            CryptoScope scans binaries, source code, and repos to identify hashes, ciphers, and protocols — ranking strength, performance, and compliance so auditors and teams can remediate with confidence.
          </p>
          <div className="flex flex-wrap gap-3 pt-2">
            <Button as="a" href="#get-started" className="bg-gradient-to-r from-emerald-400 to-cyan-500 text-black">
              <Download className="h-4 w-4" /> Download (Desktop)
            </Button>
            <Button as="a" href="#demo" className="border border-white/15 text-white/90 hover:bg-white/5">
              <Sparkles className="h-4 w-4" /> Try the Web Demo
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

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, delay: 0.1 }}
          className="relative"
        >
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
            <pre className="px-6 pb-6 text-xs sm:text-sm leading-relaxed text-white/80">
{`{"file":"/build/wallet.exe","matches":[
  {"algo":"SHA-256","type":"hash","confidence":0.98,"line":214},
  {"algo":"AES-256-GCM","type":"cipher","confidence":0.94,"line":377},
  {"algo":"RIPEMD-160","type":"hash","confidence":0.72,"line":502}
],"score":{"security":0.88,"performance":0.76,"adoption":0.91}}`}
            </pre>
          </Card>
        </motion.div>
      </Container>
    </section>
  );
}

const features = [
  {
    icon: <FileSearch className="h-5 w-5" />, title: "Multi-source scanning",
    desc: "Analyze binaries, source code, or entire GitHub repos with one click."
  },
  { icon: <Cpu className="h-5 w-5" />, title: "Static + Dynamic",
    desc: "Hybrid detection pipeline with signatures, AST, and optional Frida hooks." },
  { icon: <Gauge className="h-5 w-5" />, title: "Fast & scalable",
    desc: "Parallel scanning and caching for large workspaces and CI/CD."
  },
  { icon: <ShieldCheck className="h-5 w-5" />, title: "NIST-informed scoring",
    desc: "Weighted metrics for strength, performance, adoption, and risk." },
  { icon: <Database className="h-5 w-5" />, title: "NDJSON/JSON exports",
    desc: "Stream-friendly logs for SIEMs, notebooks, and diffable audits." },
  { icon: <Layers className="h-5 w-5" />, title: "Tiered roles",
    desc: "Free, Premium, and Admin tiers map to your workflow and governance." },
];

function Features() {
  return (
    <section id="features" className="py-20">
      <Container>
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl sm:text-4xl font-semibold">Built for auditors & secure teams</h2>
          <p className="mt-3 text-white/70">
            Actionable detections, rich context, and exports that play nicely with the rest of your toolchain.
          </p>
        </div>
        <div className="mt-10 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 10 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.4, delay: i * 0.05 }}>
              <Card className="h-full">
                <div className="flex items-center gap-3 text-emerald-300">
                  <div className="grid h-9 w-9 place-content-center rounded-xl bg-emerald-500/10 border border-emerald-400/20 text-emerald-300">
                    {f.icon}
                  </div>
                  <h3 className="text-base font-semibold text-white">{f.title}</h3>
                </div>
                <p className="mt-3 text-sm text-white/70">{f.desc}</p>
              </Card>
            </motion.div>
          ))}
        </div>
      </Container>
    </section>
  );
}

function HowItWorks() {
  const steps = [
    { icon: <GitFork className="h-5 w-5" />, title: "Ingest",
      desc: "Drop files, point to a repo, or attach build artifacts." },
    { icon: <Cpu className="h-5 w-5" />, title: "Analyze",
      desc: "Static rules + AST + optional Frida hooks for runtime hints." },
    { icon: <BarChart3 className="h-5 w-5" />, title: "Score",
      desc: "NIST-based weights and adoption metrics produce a clear ranking." },
    { icon: <Workflow className="h-5 w-5" />, title: "Report",
      desc: "Export NDJSON/JSON; diff audits over time; share in CI or PDFs." },
  ];
  return (
    <section id="how-it-works" className="py-20">
      <Container>
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl sm:text-4xl font-semibold">Pipeline at a glance</h2>
          <p className="mt-3 text-white/70">Designed for repeatable, diffable audits that map to compliance frameworks.</p>
        </div>
        <div className="mt-12 grid gap-6 lg:grid-cols-4 sm:grid-cols-2">
          {steps.map((s, i) => (
            <Card key={i} className="relative">
              <div className="flex items-center gap-3">
                <div className="grid h-9 w-9 place-content-center rounded-xl bg-cyan-500/10 border border-cyan-400/20 text-cyan-300">{s.icon}</div>
                <h3 className="font-semibold">{s.title}</h3>
              </div>
              <p className="mt-3 text-sm text-white/70">{s.desc}</p>
              {i < steps.length - 1 && (
                <div className="absolute -right-3 top-1/2 hidden translate-y-[-50%] lg:block">
                  <ChevronRight className="h-6 w-6 text-white/30" />
                </div>
              )}
            </Card>
          ))}
        </div>
      </Container>
    </section>
  );
}

function Pricing() {
  const plans = [
    {
      name: "Free",
      price: "$0",
      tagline: "For quick checks & students",
      cta: "Start Free",
      features: [
        "Single-file scans",
        "Core ruleset",
        "JSON export",
      ],
    },
    {
      name: "Premium",
      price: "$19/mo",
      tagline: "For professional audits",
      cta: "Go Premium",
      featured: true,
      features: [
        "Multi-file & repo scanning",
        "NDJSON streaming",
        "Diffable audit history",
        "Optional dynamic hooks",
      ],
    },
    {
      name: "Admin",
      price: "Custom",
      tagline: "For teams & governance",
      cta: "Talk to Sales",
      features: [
        "Role-based access",
        "Policy overrides",
        "On-prem / air-gapped",
        "SAML/SSO",
      ],
    },
  ];

  return (
    <section id="pricing" className="py-20">
      <Container>
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl sm:text-4xl font-semibold">Simple, transparent pricing</h2>
          <p className="mt-3 text-white/70">Choose a plan that matches your workflow. Upgrade anytime.</p>
        </div>
        <div className="mt-10 grid gap-6 lg:grid-cols-3">
          {plans.map((p, i) => (
            <Card key={i} className={`${p.featured ? "border-emerald-400/30 bg-emerald-400/5" : ""}`}>
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
              <Button as="a" href="#get-started" className={`mt-6 w-full justify-center ${p.featured ? "bg-gradient-to-r from-emerald-400 to-cyan-500 text-black" : "border border-white/15 text-white/90 hover:bg-white/5"}`}>
                {p.cta}
              </Button>
            </Card>
          ))}
        </div>
      </Container>
    </section>
  );
}

function FAQ() {
  const faqs = [
    { q: "What platforms are supported?", a: "Windows, macOS, and Linux for the desktop app. A lightweight web demo is also available." },
    { q: "Which languages/targets can you scan?", a: "Start with EVM/solidity sources and bytecode, common C/C++/Rust/Go/JS repos, and generic binaries. More to come." },
    { q: "How do exports work?", a: "Use JSON for single reports or NDJSON for streaming line-by-line detections that play well with SIEMs and notebooks." },
    { q: "Does it work offline?", a: "Yes. Premium and Admin tiers support full offline scanning with local rule packs." },
  ];
  return (
    <section id="faq" className="py-20">
      <Container>
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl sm:text-4xl font-semibold">Frequently asked questions</h2>
          <p className="mt-3 text-white/70">Don’t see your question? Reach out and we’ll help you evaluate the fit.</p>
        </div>
        <div className="mx-auto mt-10 max-w-3xl divide-y divide-white/10 rounded-2xl border border-white/10 bg-white/[0.03]">
          {faqs.map((f, i) => (
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
  );
}

function Footer() {
  return (
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
  );
}

export default function CryptoScopeLanding() {
  return (
    <div className="min-h-screen bg-black text-white">
      <Nav />
      <Hero />
      <Features />
      <HowItWorks />
      <Pricing />
      <FAQ />
      <Footer />
    </div>
  );
}
