# Contributing to SecXfer

Thank you for your interest in contributing to SecXfer! This document explains our branching strategy, commit conventions, and code review process.

---

## Branching Strategy

We use a **Git Flow** model:

```
master  (production releases, tagged)
  └── develop  (integration branch — all features merge here first)
        ├── feature/your-feature-name
        ├── fix/your-bug-description
        └── chore/your-maintenance-task
```

### Rules
- **Never commit directly to `master`.** All changes go through `develop` via Pull Request.
- **Feature branches** branch off `develop` and merge back into `develop`.
- **Releases** are tagged on `master` using semantic versioning (`v2.0.0`, `v2.1.0`, etc.).
- **Hotfixes** branch off `master`, fix, then merge back into both `master` and `develop`.

### Branch Naming
```
feature/add-ml-kem-768
fix/challenge-nonce-ttl
chore/update-dependencies
docs/improve-protocol-diagram
```

---

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `perf`

**Examples:**
```
feat(crypto): add ML-KEM-768 post-quantum key encapsulation
fix(django): migrate challenge nonces to database cache
docs(readme): add security disclosure section
chore(gitignore): exclude *.db and server_vault/
```

---

## Setting Up Your Development Environment

```bash
# 1. Clone the repository
git clone <repo-url>
cd secxfer

# 2. Install Python dependencies
pip install -e ".[dev]"
pip install django django-cors-headers

# 3. Set up the Django server
cd secxfer_django
python manage.py migrate
python manage.py createcachetable

# 4. Set up the Next.js frontend
cd ../secxfer_nextjs
npm install
cp .env.example .env.local   # edit with your local ports

# 5. Run tests
cd ..
pytest
```

---

## Security Vulnerability Reporting

**Do not open a public GitHub issue for security vulnerabilities.**

See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

---

## Code Review Checklist

Before submitting a Pull Request, ensure:

- [ ] All existing tests pass (`pytest`)
- [ ] New cryptographic code is reviewed against the threat model (`threat_model.md`)
- [ ] No private key material, `.key` files, or database files (`*.db`) are included
- [ ] Commit messages follow Conventional Commits format
- [ ] `README.md` is updated if architecture changes
