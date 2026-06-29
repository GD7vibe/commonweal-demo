# Commonweal — demo

A working prototype of a free, revocable QR-pass access system for public
facilities. One device shows a rotating QR pass; another scans it at the gate
and gets an instant **allow** or **barred** decision, validated server-side.
Staff can apply graduated consequences — a logged warning, a timed suspension,
or a permanent ban — each recorded with the infraction and a note.

This is a demonstration of the mechanism, not the finished service. See
**What's real vs. demo** below.

## What's in here

| File | Purpose |
|------|---------|
| `index.html` | The whole app: Citizen pass / Staff scanner / Council admin |
| `schema.sql` | The Supabase backend — paste into the SQL editor once |

## Setup

### 1. Backend (Supabase)

In your Supabase project: **SQL Editor → New query**, paste all of `schema.sql`,
press **Run**. This creates the tables, locks them with row-level security,
installs the server-side functions, and seeds one test pass.

Then change the demo signing key to something random:

```sql
update public.app_config set value = 'your-own-random-secret' where key = 'signing_key';
```

Get your **Project URL** and **anon public** key from **Project Settings → API**.

### 2. Configure the app

Edit the `CONFIG` block near the top of `index.html`:

```js
const SUPABASE_URL      = "https://YOUR-PROJECT.supabase.co";
const SUPABASE_ANON_KEY = "YOUR-ANON-PUBLIC-KEY";
```

### 3. Host it on GitHub Pages (free HTTPS — needed for the camera)

After pushing this repo to GitHub: **Settings → Pages → Source: Deploy from a
branch → `main` / `/ (root)` → Save**. After a minute your demo is live at
`https://<your-username>.github.io/<repo-name>/`.

Browsers only grant camera access over HTTPS, which Pages provides — so the
scanner works straight from that URL.

## Running the demo

- **Phone:** open the Pages URL, stay on **Citizen pass**. Optionally *Add to
  Home Screen* for a full-screen, app-like launch.
- **Laptop / tablet:** open the same URL → **Staff scanner** → **Start camera**
  → point at the phone.

A good 60-second walkthrough:

1. Scan the pass → green **Welcome in**.
2. **Council admin**: pick an infraction, add a note, choose a **bar length**,
   **Apply bar**.
3. Scan again → instant red **Entry barred** with the reason and return date.
   The phone's own pass screen shows the same: why, and the date they can return.
4. **Reinstate** (or pick the 30-second bar and wait) → scan → green again.
5. **Incident history** shows every action, infraction and note — the audit trail.

Bar lengths: 30 seconds (demo), 1/2/3 days, 1/2/3/4/8 weeks, 3/6 months, 1 year,
and permanent. Timed suspensions lift themselves automatically.

## What's real vs. demo

**Real:** tokens are signed and verified inside the Postgres database; expiry,
live status, site scope, and auto-lifting suspensions all run server-side. A
revoked pass is dead on the next scan regardless of anything cached on the phone.

**Demo only, by design:**

- The admin functions are open to the public key. **In production they must sit
  behind staff authentication** (Supabase Auth + a staff role). This is the next
  build step.
- No photographs (Tier 0 only), matching the spec default.

## Security note for a public repo

The Supabase **anon key is designed to be exposed** in browser code — its safety
comes entirely from the row-level security in `schema.sql`, which this project
sets up. Committing it for Pages to serve is normal.

But because the admin functions are open in this demo, anyone who finds a public
repo's anon key could call them. So: use a **throwaway Supabase project** for the
demo, don't reuse it for anything real, and never commit the real `signing_key`
(keep the placeholder in `schema.sql` and set the real value via the SQL `update`
above). Add staff authentication before this is anything more than a demo.

## License

No license is set. Add one (e.g. MIT) via GitHub's **Add file → Create new file →
`LICENSE`** if you want others to be able to reuse it.
