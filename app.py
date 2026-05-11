"""
Multi-Algorithm File Encryption/Decryption System
Streamlit GUI — supports Triple DES, AES, RSA, ECC, ElGamal
"""

import streamlit as st
import base64
import json
import time
import os
import io
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")

from crypto_algorithms import (
    TripleDESCrypto, AESCrypto, RSACrypto,
    ECCCrypto, ElGamalCrypto, benchmark_algorithm
)

# ──────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="CryptoSuite — File Encryption System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# Custom CSS
# ──────────────────────────────────────────────
st.markdown("""
<style>
    .main-title {
        font-size: 2.4rem; font-weight: 800;
        background: linear-gradient(135deg, #1a237e, #0d47a1, #1565c0);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        padding-bottom: 0.3rem;
    }
    .algo-badge {
        display:inline-block; padding:4px 12px; border-radius:20px;
        font-size:0.8rem; font-weight:600; margin:2px;
        background:#e3f2fd; color:#0d47a1; border:1px solid #90caf9;
    }
    .stat-card {
        background: linear-gradient(135deg, #f8f9ff, #e8eaf6);
        border-radius: 12px; padding: 18px; text-align:center;
        border: 1px solid #c5cae9;
    }
    .stat-number { font-size:2rem; font-weight:800; color:#1a237e; }
    .stat-label  { font-size:0.85rem; color:#5c6bc0; margin-top:4px; }
    .info-box {
        background:#e8f5e9; border-left:4px solid #43a047;
        border-radius:6px; padding:12px; margin:8px 0;
    }
    .warn-box {
        background:#fff8e1; border-left:4px solid #ffa000;
        border-radius:6px; padding:12px; margin:8px 0;
    }
    div[data-testid="stExpander"] { border:1px solid #c5cae9; border-radius:10px; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# Session State
# ──────────────────────────────────────────────
for k, v in {
    "sym_key": None, "priv_key": None, "pub_key": None,
    "ecc": None, "elgamal": None,
    "encrypted_bytes": None, "decrypted_bytes": None,
    "enc_time": 0.0, "dec_time": 0.0,
    "bench_results": None,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ──────────────────────────────────────────────
# Helper: algo metadata
# ──────────────────────────────────────────────
ALGO_INFO = {
    "Triple DES": {
        "type": "Symmetric", "key_size": "168-bit",
        "block": "64-bit", "mode": "CBC",
        "desc": "Triple DES applies DES cipher three times to each block. Considered legacy but still widely used in banking systems.",
        "pros": ["Battle-tested since 1998", "Hardware support"], "cons": ["Slow", "Small block size (64-bit)"],
    },
    "AES": {
        "type": "Symmetric", "key_size": "256-bit",
        "block": "128-bit", "mode": "CBC",
        "desc": "AES (Advanced Encryption Standard) is the gold standard for symmetric encryption. Used in TLS, disk encryption, and more.",
        "pros": ["Very fast", "Secure", "Hardware acceleration (AES-NI)"], "cons": ["Requires secure key exchange"],
    },
    "RSA": {
        "type": "Asymmetric", "key_size": "2048-bit",
        "block": "N/A", "mode": "OAEP",
        "desc": "RSA is the most widely used public-key algorithm. Security relies on the difficulty of factoring large integers.",
        "pros": ["Public-key (no shared secret)", "Digital signatures"], "cons": ["Slow for large data", "Key size growing"],
    },
    "ECC": {
        "type": "Asymmetric (Hybrid)", "key_size": "256-bit (P-256)",
        "block": "N/A", "mode": "ECIES",
        "desc": "Elliptic Curve Cryptography provides equivalent security to RSA with much smaller keys. Used in TLS 1.3, SSH, and Bitcoin.",
        "pros": ["Smaller keys", "Faster than RSA", "Strong security"], "cons": ["More complex implementation"],
    },
    "ElGamal": {
        "type": "Asymmetric (Hybrid)", "key_size": "1024-bit prime",
        "block": "N/A", "mode": "Hybrid+AES",
        "desc": "ElGamal encryption is based on the Diffie-Hellman key exchange. Each encryption is randomized (semantically secure).",
        "pros": ["Semantically secure", "Randomized ciphertext"], "cons": ["Ciphertext expansion", "Slower key gen"],
    },
}

SYMMETRIC = ["Triple DES", "AES"]
ASYMMETRIC = ["RSA", "ECC", "ElGamal"]


# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔐 CryptoSuite")
    st.markdown("---")
    page = st.radio("Navigate", ["🏠 Home", "🔒 Encrypt / Decrypt", "📊 Performance", "📚 Algorithm Info"])
    st.markdown("---")
    st.markdown("**Supported Algorithms**")
    for a in ALGO_INFO:
        badge_color = "#e3f2fd" if ALGO_INFO[a]["type"].startswith("Sym") else "#fce4ec"
        txt_color   = "#0d47a1" if ALGO_INFO[a]["type"].startswith("Sym") else "#880e4f"
        st.markdown(
            f'<span class="algo-badge" style="background:{badge_color};color:{txt_color}">{a}</span>',
            unsafe_allow_html=True,
        )
    st.markdown("---")
    st.caption("Built with Python · PyCryptodome · Streamlit")


# ══════════════════════════════════════════════
# PAGE: HOME
# ══════════════════════════════════════════════
if page == "🏠 Home":
    st.markdown('<p class="main-title">🔐 CryptoSuite</p>', unsafe_allow_html=True)
    st.markdown("##### Multi-Algorithm File Encryption & Decryption System")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown('<div class="stat-card"><div class="stat-number">5</div><div class="stat-label">Algorithms</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="stat-card"><div class="stat-number">2</div><div class="stat-label">Symmetric</div></div>', unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="stat-card"><div class="stat-number">3</div><div class="stat-label">Asymmetric</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown('<div class="stat-card"><div class="stat-number">∞</div><div class="stat-label">File Types</div></div>', unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### How It Works")

    cols = st.columns(5)
    steps = [
        ("📁", "Upload File", "Any file type supported"),
        ("⚙️", "Choose Algorithm", "5 algorithms available"),
        ("🔑", "Generate Keys", "Auto key generation"),
        ("🔒", "Encrypt / Decrypt", "One-click operation"),
        ("📥", "Download", "Save encrypted file"),
    ]
    for col, (icon, title, desc) in zip(cols, steps):
        with col:
            st.markdown(f"**{icon} {title}**")
            st.caption(desc)

    st.markdown("---")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Symmetric Algorithms")
        for a in SYMMETRIC:
            with st.expander(f"🔵 {a}"):
                st.markdown(f"**Key Size:** {ALGO_INFO[a]['key_size']}  |  **Mode:** {ALGO_INFO[a]['mode']}")
                st.markdown(ALGO_INFO[a]['desc'])

    with col2:
        st.markdown("### Asymmetric Algorithms")
        for a in ASYMMETRIC:
            with st.expander(f"🔴 {a}"):
                st.markdown(f"**Key Size:** {ALGO_INFO[a]['key_size']}  |  **Mode:** {ALGO_INFO[a]['mode']}")
                st.markdown(ALGO_INFO[a]['desc'])


# ══════════════════════════════════════════════
# PAGE: ENCRYPT / DECRYPT
# ══════════════════════════════════════════════
elif page == "🔒 Encrypt / Decrypt":
    st.markdown("## 🔒 Encrypt & Decrypt Files")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### ⚙️ Configuration")
        algo = st.selectbox("Select Algorithm", list(ALGO_INFO.keys()))
        operation = st.radio("Operation", ["Encrypt", "Decrypt"], horizontal=True)

        info = ALGO_INFO[algo]
        st.markdown(f"""
        <div class="info-box">
        <b>{algo}</b> · {info['type']} · Key: {info['key_size']} · Mode: {info['mode']}<br>
        <small>{info['desc']}</small>
        </div>
        """, unsafe_allow_html=True)

        # Key management
        st.markdown("### 🔑 Key Management")

        if algo in SYMMETRIC:
            if st.button("🎲 Generate New Key", use_container_width=True):
                if algo == "Triple DES":
                    st.session_state.sym_key = TripleDESCrypto.generate_key()
                else:
                    st.session_state.sym_key = AESCrypto.generate_key()
                st.success("Key generated!")

            if st.session_state.sym_key:
                st.text_area("Secret Key (Base64)", base64.b64encode(st.session_state.sym_key).decode(), height=80)
                st.markdown('<div class="warn-box">⚠️ Save this key! You need it to decrypt.</div>', unsafe_allow_html=True)

            key_input = st.text_area("Or paste existing key (Base64):", height=80)
            if key_input:
                try:
                    st.session_state.sym_key = base64.b64decode(key_input)
                    st.success("Key loaded.")
                except Exception:
                    st.error("Invalid Base64 key.")

        else:  # Asymmetric
            if st.button("🎲 Generate Key Pair", use_container_width=True):
                with st.spinner("Generating..."):
                    if algo == "RSA":
                        priv, pub = RSACrypto.generate_keypair()
                    elif algo == "ECC":
                        ecc = ECCCrypto()
                        st.session_state.ecc = ecc
                        priv, pub = ecc.generate_keypair()
                    else:
                        eg = ElGamalCrypto()
                        st.session_state.elgamal = eg
                        priv, pub = eg.generate_keypair()
                    st.session_state.priv_key = priv
                    st.session_state.pub_key  = pub
                st.success("Key pair generated!")

            if st.session_state.pub_key:
                st.text_area("Public Key", st.session_state.pub_key.decode()[:200] + "...", height=80)
            if st.session_state.priv_key:
                st.text_area("Private Key (keep secret!)", st.session_state.priv_key.decode()[:200] + "...", height=80)

    with col2:
        st.markdown("### 📁 File Operation")
        uploaded = st.file_uploader(
            "Upload file to encrypt/decrypt",
            type=None, key="file_uploader"
        )

        if uploaded:
            data = uploaded.read()
            st.info(f"📄 **{uploaded.name}** — {len(data):,} bytes ({len(data)/1024:.1f} KB)")

            if st.button(f"{'🔒 Encrypt' if operation=='Encrypt' else '🔓 Decrypt'} File", use_container_width=True, type="primary"):
                try:
                    with st.spinner(f"{'Encrypting' if operation=='Encrypt' else 'Decrypting'}..."):
                        t0 = time.perf_counter()

                        if algo == "Triple DES":
                            key = st.session_state.sym_key
                            if not key: raise ValueError("Generate or enter a key first.")
                            result = TripleDESCrypto.encrypt(data, key) if operation == "Encrypt" else TripleDESCrypto.decrypt(data, key)

                        elif algo == "AES":
                            key = st.session_state.sym_key
                            if not key: raise ValueError("Generate or enter a key first.")
                            result = AESCrypto.encrypt(data, key) if operation == "Encrypt" else AESCrypto.decrypt(data, key)

                        elif algo == "RSA":
                            if not st.session_state.pub_key: raise ValueError("Generate a key pair first.")
                            if operation == "Encrypt":
                                result = RSACrypto.encrypt(data, st.session_state.pub_key)
                            else:
                                result = RSACrypto.decrypt(data, st.session_state.priv_key)

                        elif algo == "ECC":
                            if not st.session_state.ecc: st.session_state.ecc = ECCCrypto()
                            ecc = st.session_state.ecc
                            if not st.session_state.pub_key: raise ValueError("Generate a key pair first.")
                            result = ecc.encrypt(data, st.session_state.pub_key) if operation == "Encrypt" else ecc.decrypt(data, st.session_state.priv_key)

                        elif algo == "ElGamal":
                            if not st.session_state.elgamal: st.session_state.elgamal = ElGamalCrypto()
                            eg = st.session_state.elgamal
                            if not st.session_state.pub_key: raise ValueError("Generate a key pair first.")
                            result = eg.encrypt(data, st.session_state.pub_key) if operation == "Encrypt" else eg.decrypt(data, st.session_state.priv_key)

                        elapsed = time.perf_counter() - t0

                    st.success(f"✅ {operation}ion complete in **{elapsed*1000:.2f} ms**")

                    # Metrics
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Input Size",  f"{len(data):,} B")
                    m2.metric("Output Size", f"{len(result):,} B")
                    m3.metric("Time", f"{elapsed*1000:.1f} ms")

                    ext = ".enc" if operation == "Encrypt" else ".dec"
                    out_name = uploaded.name + ext
                    st.download_button(
                        label=f"📥 Download {out_name}",
                        data=result,
                        file_name=out_name,
                        mime="application/octet-stream",
                        use_container_width=True,
                    )

                except Exception as e:
                    st.error(f"❌ Error: {e}")


# ══════════════════════════════════════════════
# PAGE: PERFORMANCE
# ══════════════════════════════════════════════
elif page == "📊 Performance":
    st.markdown("## 📊 Algorithm Performance Benchmarks")

    st.markdown("""
    Compare encryption and decryption speeds across all five algorithms.
    Benchmarks run locally on random data of various sizes.
    """)

    sizes = st.multiselect("Data sizes to benchmark (KB):", [1, 10, 50, 100], default=[1, 10])
    algos_to_bench = st.multiselect("Algorithms:", list(ALGO_INFO.keys()), default=list(ALGO_INFO.keys()))

    if st.button("▶️ Run Benchmarks", type="primary", use_container_width=True):
        results = {}
        progress = st.progress(0)
        status = st.empty()

        for i, algo in enumerate(algos_to_bench):
            status.text(f"Benchmarking {algo}...")
            try:
                results[algo] = benchmark_algorithm(algo, sizes)
            except Exception as e:
                results[algo] = {"error": str(e)}
            progress.progress((i+1)/len(algos_to_bench))

        st.session_state.bench_results = results
        status.empty()
        progress.empty()

    if st.session_state.bench_results:
        res = st.session_state.bench_results

        # Build summary table
        rows = []
        for algo, data in res.items():
            if "error" in data: continue
            for size_key, metrics in data.items():
                rows.append({
                    "Algorithm": algo,
                    "Data Size": size_key,
                    "Encrypt (ms)": metrics["encrypt_ms"],
                    "Decrypt (ms)": metrics["decrypt_ms"],
                    "Total (ms)":   metrics["total_ms"],
                })

        if rows:
            df = pd.DataFrame(rows)
            st.markdown("### Results Table")
            st.dataframe(df, use_container_width=True)

            # Bar chart per size
            for sz in df["Data Size"].unique():
                sub = df[df["Data Size"] == sz]
                fig, ax = plt.subplots(figsize=(8, 3.5))
                x = range(len(sub))
                bars1 = ax.bar([i-0.2 for i in x], sub["Encrypt (ms)"], width=0.35, label="Encrypt", color="#1565c0", alpha=0.85)
                bars2 = ax.bar([i+0.2 for i in x], sub["Decrypt (ms)"], width=0.35, label="Decrypt", color="#c62828", alpha=0.85)
                ax.set_xticks(list(x))
                ax.set_xticklabels(sub["Algorithm"], rotation=15)
                ax.set_ylabel("Time (ms)")
                ax.set_title(f"Encryption vs Decryption Time — {sz} Data")
                ax.legend()
                ax.grid(axis='y', alpha=0.3)
                for b in list(bars1)+list(bars2):
                    ax.text(b.get_x()+b.get_width()/2, b.get_height()+0.1, f"{b.get_height():.1f}", ha='center', va='bottom', fontsize=7)
                fig.tight_layout()
                st.pyplot(fig)
                plt.close(fig)

            # Radar summary (total time for 1KB if available)
            st.markdown("### 🏆 Algorithm Comparison Summary")
            comp_rows = []
            for algo, data in res.items():
                if "error" in data: continue
                first_key = list(data.keys())[0]
                comp_rows.append({
                    "Algorithm": algo,
                    "Type": ALGO_INFO[algo]["type"],
                    "Key Size": ALGO_INFO[algo]["key_size"],
                    f"Encrypt {first_key} (ms)": data[first_key]["encrypt_ms"],
                    f"Decrypt {first_key} (ms)": data[first_key]["decrypt_ms"],
                })
            st.dataframe(pd.DataFrame(comp_rows), use_container_width=True)


# ══════════════════════════════════════════════
# PAGE: ALGORITHM INFO
# ══════════════════════════════════════════════
elif page == "📚 Algorithm Info":
    st.markdown("## 📚 Algorithm Reference")

    for algo, info in ALGO_INFO.items():
        color = "#1a237e" if info["type"].startswith("Sym") else "#880e4f"
        with st.expander(f"{'🔵' if info['type'].startswith('Sym') else '🔴'} {algo} — {info['type']}", expanded=False):
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown(f"**Description:** {info['desc']}")
                st.markdown("**✅ Advantages:**")
                for p in info["pros"]: st.markdown(f"  - {p}")
                st.markdown("**❌ Limitations:**")
                for c in info["cons"]: st.markdown(f"  - {c}")

            with c2:
                st.markdown(f"**Key Size:** `{info['key_size']}`")
                st.markdown(f"**Block Size:** `{info['block']}`")
                st.markdown(f"**Mode:** `{info['mode']}`")
                st.markdown(f"**Type:** `{info['type']}`")

    st.markdown("---")
    st.markdown("### 🔍 Algorithm Comparison Table")
    comp = []
    for algo, info in ALGO_INFO.items():
        comp.append({
            "Algorithm": algo,
            "Type": info["type"],
            "Key Size": info["key_size"],
            "Block/Mode": f"{info['block']} / {info['mode']}",
            "Best Use Case": {
                "Triple DES": "Legacy banking systems",
                "AES": "General-purpose encryption",
                "RSA": "Key exchange, digital signatures",
                "ECC": "Mobile / IoT / TLS 1.3",
                "ElGamal": "Academic / PGP-style systems",
            }[algo],
        })
    st.dataframe(pd.DataFrame(comp), use_container_width=True)
