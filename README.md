# U-Choice Liquor POS

A point-of-sale app with a real backend, user accounts, and role-based
access control — built from the original standalone (localStorage-only)
HTML file. All the original business logic (fractional sales, sales
history, daily/weekly/monthly/yearly sales, profit and expenditure
reports) is unchanged.

## Structure

```
pos-app/
├── server.js          # Express backend: auth, user management, business data API
├── reset-password.js  # emergency CLI password reset (server access required)
├── package.json
├── data.json          # created automatically — business records (products, sales, ...)
├── users.json         # created automatically — accounts, roles, permissions
└── public/
    └── index.html     # the frontend (HTML/CSS/JS), talking to the API
```

## Installing and running it

1. Install [Node.js](https://nodejs.org) (LTS) if you don't have it — check with `node -v`.
2. Unzip this project anywhere on your computer.
3. Open a terminal in the `pos-app` folder.
4. Install dependencies (one time):
   ```bash
   npm install
   ```
5. Start the server:
   ```bash
   npm start
   ```
   You should see:
   ```
   No users found — created default admin account: username "admin", password "admin123". Please change this password after logging in.
   U-Choice Liquor POS server running on http://localhost:3000
   ```
6. Open **http://localhost:3000** in a browser and log in with:
   - **Username:** `admin`
   - **Password:** `admin123`

   Change this password immediately from **Settings → My Account**.

To let other tills/devices on the same network use it, run the server on a
machine's IP address and open `http://<that-computer's-IP>:3000` from the
other devices. You can also change the port:
```bash
PORT=8080 npm start
```

## Admin and user accounts

- **Admin** accounts always have full access to every section (Sales,
  Stock, Reports, Profit, Expenditure, History, Settings, and Users).
- From the **Users** tab (admin only), an admin can:
  - Create new attendant accounts with a username and password.
  - Choose exactly which sections each attendant can see (checkboxes for
    Sales, Stock, Reports, Profit, Expenditure, History, Settings).
  - Edit an existing user's role or permissions at any time.
  - Reset a user's password.
  - Delete a user (an admin can't delete their own account, and the last
    remaining admin account can't be deleted, so you can never lock
    yourself out).
- Any logged-in user can change their own password from **Settings → My
  Account**.
- Every sale and stock change is now recorded against the actual logged-in
  username, and Sales History lets you filter by attendant.

### How access restriction works

- The frontend hides the nav tabs and sections a user isn't permitted to
  use, based on the permissions returned at login.
- **The backend enforces the same permissions independently**, per
  resource. Business data is no longer one shared blob — it's split into
  separate, permission-checked endpoints:

  | Endpoint | Requires |
  |---|---|
  | `GET /api/products` | sales, stock, reports, or profit |
  | `POST /api/products`, `PUT /api/products/:id/add-stock`, `DELETE /api/products/:id` | stock |
  | `PUT /api/products/:id` (full edit — size, buying price, selling price, stock) | **admin only** |
  | `GET /api/sales` | sales, reports, profit, or history |
  | `POST /api/sales` (complete a sale) | sales |
  | `DELETE /api/sales[/:id]` | history |
  | `GET/POST/DELETE /api/expenditures[/:id]` | expenditure |
  | `GET/PUT /api/settings` | settings |
  | `/api/users*`, `/api/audit-log*` | admin only |

  Admins bypass all of these checks automatically. For everyone else, the
  server checks the requesting user's *actual* stored permissions on every
  request — not anything the client claims — so an attendant without
  `expenditure` access gets a `403` from `/api/expenditures` even if they
  call the API directly, bypassing the UI entirely. This was verified with
  direct `curl` requests during development (a sales-only account was
  confirmed to get `403` on products-write, expenditures,
  sales-history-delete, and settings).
- Completing a sale is handled entirely server-side: the server validates
  there's enough stock for every cart item, decrements stock, and records
  the sale atomically, so two attendants selling the last bottle at the
  same moment can't both succeed.
- Product seeding (the default catalog) now happens once, server-side, on
  first run — instead of being duplicated in the browser.

## Stock editing (admin only)

- The old **+ Add Stock** button on each product row is now an **Edit**
  button, admin-only. It opens a form where the admin can update the
  product's **size, buying price, selling price, and stock quantity** all
  at once (setting them directly, not just incrementing stock). This is
  enforced both in the UI (the button only renders for admins) and on the
  server (`PUT /api/products/:id` requires `requireAdmin`), so an
  attendant can't call it directly either.
- Non-admin attendants with `stock` access can still use **Add Product**
  (which also adds initial/extra stock for a brand-new or duplicate-name
  item) and **Delete** a product, exactly as before — only "edit an
  existing product's numbers" moved to admin-only.
- The **📋 Stock Activity log** (a separate feature that used to track
  every stock addition, edit and deletion as a live table) has been
  removed from the Stock page. Every product add/edit/delete is still
  recorded — first in the **🕵 Audit Report**, and now also summarized
  in the new **periodic stock report** below.

## Stock Level Report (admin only)

The Stock page has a **📦 Stock Level Report** panel (below the product
table, admin-only) that shows what's actually on the shelf, not a log of
past actions:

- For a chosen **Daily / Weekly / Monthly / Yearly** period, it lists
  every product's **current stock**, **stock value** (stock × buying
  price), and **quantity sold during that period** — plus summary cards
  for total units in stock, total stock value, total units sold, and how
  many products are low on stock (≤5 units).
- "Sold in period" counts every sale that left the shelf in that window,
  including credit sales that haven't been paid yet — this report is
  about inventory movement, not revenue, so it doesn't wait for payment.
- This replaced an earlier version that pulled from the Audit Report
  (a log of "Product added / edited / deleted" events); that was
  activity history, not stock levels, which made it hard to answer "how
  much do I actually have left."
- **🖨 Generate PDF** exports the currently selected period.

## Credit sales don't count as revenue until paid

Sales sold on credit (see **Pending Payments** below) still leave the
shelf immediately, but their KES amount is **excluded from every revenue
figure** — Today's Activity, the Manager Dashboard, Daily/Periodic Sales
Reports, and the Profit Report — for as long as they're outstanding:

- The moment a credit sale is fully paid off (via **Record Payment** on
  the Pending tab), it starts counting in all of those reports
  automatically, under its original sale date — no manual step needed.
- A partially-paid credit sale still counts as KES 0 everywhere in
  reporting until the *entire* balance is cleared; there's no
  partial-credit toward the totals.
- Each report now shows a small note — "Credit sales are excluded here
  until fully paid — see the Pending tab" — so this isn't a silent gap.
- The Sales History and Pending tabs still show every sale, including
  outstanding ones (with a "Pending KES X" badge), since those are meant
  to be a complete record, not a revenue tally.

## Deleting a sale restores its stock

Previously, deleting a sale from History (or clearing all history) left
stock levels untouched — the app said as much in the confirmation
message. That's now been reversed: deleting a sale (single or via
**Clear All History**) adds every item in it back onto the matching
product's stock, atomically, before removing the record. This happens
server-side, so it can't be skipped or half-applied. The confirmation
dialogs and Audit Report entries were updated to reflect this.

## Deleting sales history is admin only

Any user with `history` access can still view Sales History and search/
filter it, but deleting a single sale or clearing all history is now
**restricted to admin accounts**:

- The **Delete** button per row, and the **Clear All History** button,
  are hidden from non-admin users in the UI.
- This is also enforced on the server (`DELETE /api/sales/:id` and
  `DELETE /api/sales` both require the `admin` role now, not just the
  `history` permission), so a non-admin attendant gets a `403` even if
  they call the API directly.

## Reports scoped to the logged-in attendant

- The **📊 Reports** tab (Manager Dashboard + Daily/Periodic Analysis) now
  shows **admins** the sales of every attendant, but shows **non-admin**
  users only the sales **they personally completed**. A note at the top
  of the tab makes this explicit for attendants.
- This is a front-end scoping of the already-loaded sales data (the same
  `/api/sales` endpoint used by History/Profit/the Sales tab, which are
  unchanged). If you need this enforced at the API level too — so a
  determined attendant can't see the full list even via direct API
  calls — let your developer know.
- **Profit Periodic Report** and **Sales History** were left as-is (still
  show full data to anyone with `profit`/`history` access) since only
  "Reports" was in scope for this change; ask if you'd like the same
  attendant-only scoping applied there.

## Generate PDF reports

Three tabs now have a **🖨 Generate … PDF** button — Stock, Expenditure,
and Reports. Each opens a print-formatted page in a new tab and triggers
your browser's print dialog; choose **"Save as PDF"** (or "Microsoft
Print to PDF" / "Save to PDF" depending on your browser) as the
destination. This uses the browser's built-in printing, so it works
fully offline with no extra libraries:

- **Stock PDF**: the current stock list.
- **Expenditure PDF**: all expenditures plus whatever periodic
  expenditure analysis is currently on screen (run "Analyze Expenditure"
  first if you want that section included).
- **Reports PDF**: the Manager Dashboard summary cards plus whatever
  daily/periodic report is currently on screen (run "View Day" or
  "Analyze Period" first). For non-admins this is scoped to their own
  sales, matching what's shown in the Reports tab.

## Forgot password (no email required)

Every account can set a personal **recovery question** so it can reset
its own password from the login screen without an admin or an email
server:

- **Settings → My Account → Recovery Question**: pick one of the preset
  questions (or write your own), give an answer, confirm with your
  current password, and save. Any user — attendant or admin — can set
  this for themselves.
- **On the login screen**, click **Forgot password?**, enter your
  username, answer your question, and choose a new password. This works
  entirely offline — no email or SMS is sent.
- If an account has no recovery question set, the login screen tells the
  person to ask an admin to reset their password instead (admins can
  still do this from **Users → Reset Password** as before).
- A successful reset immediately signs that account out everywhere (all
  active sessions are invalidated) and is recorded in the Audit Report.
- **If the only admin account forgets its password and never set a
  recovery question**, use the included break-glass script directly on
  the server (this needs file access to the machine running the app, by
  design — it can't be triggered remotely):
  ```bash
  node reset-password.js admin YourNewPassword123
  ```
  This rewrites that one account's password in `users.json` and clears
  any recovery question on it (since whoever is running the script
  clearly can't answer it right now). No server restart is needed —
  log in immediately with the new password. Setting a recovery question
  for at least one admin account right away is strongly recommended so
  you never need this script.

## Colors and look

The interface was restyled around a wine-and-gold palette (deep burgundy
`#7A1F3D`, near-black wine `#3D0E1E`, and a warm gold accent `#D9A441`)
in place of the previous generic blue theme — fitting for a liquor
retail brand and giving active states (selected nav tab, badges, quick
buttons) a warmer, more distinctive look. The login screen's background
image (an external Unsplash photo) was replaced with a self-contained
CSS gradient, so the login page now renders correctly even with no
internet connection, which matters for a POS meant to run on a local
shop network.

## Audit Report

A new **🕵 Audit Report** tab (admin-only) shows a searchable, filterable
log of activity across the whole system:

- **Security events** — logins (successful and failed), logouts, password
  changes, and every user created/updated/deleted — are recorded
  automatically **by the server itself**, using the identity from the
  verified session token. These can't be forged or skipped by the
  frontend.
- **Business events** — sales completed/deleted, stock added, products
  added/deleted, expenditures added/deleted, settings changes, and the
  various "clear" actions — are logged via a small API call the frontend
  makes right after each action. The action text is client-supplied, but
  *who* did it is always the server-verified logged-in user, not whatever
  the client claims.
- Filter by keyword, category, or **period** (All time / Daily / Weekly /
  Monthly / Yearly with an anchor date — the same period picker used
  elsewhere in the app); clear the entire log (admin only) if you need to
  start fresh.
- Entries are stored in `audit.json`, capped at the most recent 5,000
  entries to keep the file from growing indefinitely.

## Pending Payments (Credit Sales)

A new **🕒 Pending** tab lets you sell now and collect payment later:

- **At checkout**, tick **"Sell on credit (payment pending / due later)"**
  to reveal customer name (required), phone (optional), amount paid now
  (a deposit — 0 if nothing was paid yet), and an optional due date. The
  sale still deducts stock immediately, exactly like a normal sale — only
  the payment is tracked as outstanding.
- **The Pending tab** lists every credit sale with its total, amount
  paid, remaining balance, due date, and status (Outstanding / Overdue /
  Settled). Click **Record Payment** on any outstanding sale to log a
  full or partial payment — the balance updates immediately, and the
  sale flips to "Settled" once it reaches zero. Every partial payment is
  timestamped and attributed to whoever collected it.
- **Periodic view**: filter by All time / Daily / Weekly / Monthly /
  Yearly (by the date the sale was made), plus a status filter
  (Outstanding only / Settled only / All) and a search box for customer
  name, phone, or attendant. Summary cards show total outstanding
  balance, number of open credit sales, amount collected in the selected
  period, and how many are overdue.
- **Scoped like Reports**: admins see every attendant's credit sales;
  non-admin users (with `sales` access) see only credit sales they
  personally recorded, so each attendant follows up on their own debtors.
- **🖨 Generate Pending Report PDF** exports the currently filtered list.
- The Sales History table also shows a small **"Pending KES X"** badge
  next to the payment method for any sale that still has a balance owed.
- Every credit sale and payment collected is also logged in the Audit
  Report (`Sale completed (pending payment)` and `Pending payment
  collected`).

## Notes

- User accounts are stored in `users.json`; business records live in
  `data.json`; the audit trail lives in `audit.json`. All three are plain
  JSON files on the server — no external database required.
- Login sessions are kept in memory, so restarting the server logs
  everyone out (they just log back in).
- Passwords are hashed with Node's built-in `scrypt` (never stored in
  plain text).
