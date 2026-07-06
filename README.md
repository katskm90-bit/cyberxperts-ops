# Cyberxperts Operations · Setup

Internal operations platform for Cyberxperts. Skeleton stage: login, mandatory
second factor, role detection, and department aware routing, with placeholders
for every module. No module logic yet.

Built the same way as HymnDesk Control: plain HTML, CSS, and JavaScript, no
build step, no npm, nothing to compile. GitHub Pages serves the files exactly
as they are.

## File overview

```
cyberxperts-ops/
├── index.html          The single HTML shell, every screen and module lives here
├── style.css            All styling
├── manifest.json        PWA manifest
├── sw.js                Service worker, caches the app shell for offline use
├── schema.sql            Run once in Supabase, creates every table and access rule
├── bootstrap_admin.sql   Run once, after creating yourself, to become System Super User
├── js/
│   ├── config.js         Your Supabase URL and anon key go here
│   └── app.js             Login, MFA, routing, everything else
├── brand/
│   └── logo.png
└── icons/
    ├── icon-192.png
    └── icon-512.png
```

## How the login works

1. You create your own account directly in Supabase, under Authentication,
   then Users, then Add User.
2. You run `bootstrap_admin.sql` once, with your details filled in, so your
   account is marked as System Super User.
3. On first sign in, you're asked to set up a second factor using an
   authenticator app such as Zoho OneAuth. This is mandatory for every
   account, with no exceptions.
4. From then on, signing in asks for the current six digit code from that
   app, every time.
5. Once signed in, the app reads your profile, works out your department and
   role, and only shows you the parts of the system you're allowed to see.

There is no sign up page. New accounts for other staff are created the same
way you created your own, one at a time, by whoever holds System Super User.
This is deliberate, given the sensitivity of what this system will hold.

## Setting up Supabase

1. Create a project at supabase.com if one does not already exist for this.
2. Open the SQL editor and run everything in `schema.sql`.
3. Under Authentication, then Providers, confirm email and password sign in
   is enabled.
4. Under Authentication, then Multi-Factor Authentication, turn on TOTP.
5. Under Project Settings, then API, copy the Project URL and the anon
   public key. Paste both into `js/config.js`, replacing the two placeholder
   lines. These two values are safe to leave visible in the file. Nothing is
   protected by hiding them, protection comes from the access rules created
   by `schema.sql`.
6. Under Authentication, then Users, click Add User, and create your own
   login.
7. Copy your new user id from that list, and use it to fill in
   `bootstrap_admin.sql`, then run that file in the SQL editor.

## Putting it on GitHub Pages

1. Create a repository, or reuse the existing one, and remove anything left
   over from the earlier build attempt so the two do not mix.
2. Upload every file and folder from this project using GitHub's uploader.
   Since nothing here starts with a dot, everything will show up and drag in
   normally this time.
3. In that repository, go to Settings, then Pages, and set Source to
   "Deploy from a branch", with the branch set to main and the folder set to
   root.
4. Wait a minute or two, then refresh that same Pages settings page. A
   message will appear near the top saying the site is live, with the
   address.

Nothing else is required. No secrets, no variables, no build to watch for a
green tick. If the site shows a blank page after this, it almost always
means `js/config.js` still has the placeholder text in it rather than your
real Supabase values.

## What is deliberately not built yet

- Real workflow logic inside each module.
- The configurable thresholds in Settings have no editing screen yet.
- The compliance document list and any second or later accounts still need
  to be added by hand.
