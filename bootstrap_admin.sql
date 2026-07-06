-- Run this once, after you have created your own login in Supabase, under
-- Authentication, then Users, then Add User.
--
-- Before running this, replace the three placeholder values below with your
-- own. Your user id is shown in the Authentication user list once created.

insert into public.profiles (id, full_name, email, department, role_tier, mfa_enrolled)
values (
  'PASTE-YOUR-USER-ID-HERE',
  'PASTE-YOUR-FULL-NAME-HERE',
  'PASTE-YOUR-EMAIL-HERE',
  null,
  'system',
  false
)
on conflict (id) do update set role_tier = 'system';

-- After this runs, sign in with the email and password you created. You
-- will be asked to set up your second factor on that first sign in.
