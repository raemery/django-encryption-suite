# Simple teams

`encryption_suite.contrib.simpleteams` is an optional Django app for projects that
have no team or tenant model of their own. It ships a team model, a membership
model, the [silo adapter](silo-adapters.md#simpleteamsiloadapter), the middleware
that makes a user's team the current silo, and an admin. Each team's data is
encrypted under that team's own keys, and the only thing to write is settings.

What keeps it simple is that each user belongs to at most one team. The database
enforces this, so the middleware never has to choose between teams. A user with no
team has no current silo, and encrypted access fails for them until an admin adds
them to a team.

The app imports no third-party framework and needs no extra. It creates tables
only when it is in `INSTALLED_APPS`. A project whose users need several teams, or
that already has a team model, wants
[`GenericModelSiloAdapter`](silo-adapters.md#genericmodelsiloadapter) over its own
model instead.

## Setup

Add the app and its middleware, below `AuthenticationMiddleware`, and bind the
`default` key set to the app's silo adapter:

```python
INSTALLED_APPS = [
    # ...
    "encryption_suite",
    "encryption_suite.contrib.simpleteams",
]

MIDDLEWARE = [
    # ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "encryption_suite.contrib.simpleteams.middleware.SimpleTeamSiloMiddleware",
]

ENCRYPTION = {
    "ENV_KEY_STORES": {"login": {"KEKS": {1: os.environ["ENC_LOGIN_KEK"]}}},
    "KEY_SETS": {
        "default": {
            "silo": "encryption_suite.contrib.simpleteams.adapter.SimpleTeamSiloAdapter",
            "key_store": "login",
        },
        "system": {"key_store": "login"},  # no silo: the system key set always uses the system silo
    },
}
```

Then run `python manage.py migrate`.

**`ENV_KEY_STORES` is required.** A team's name is a
[`key_set="system"` column](system-wide-silos.md) with a blind index, so the app
needs an env key store for the `system` key set. `manage.py check` reports it
missing (`E040`). See [`ENV_KEY_STORES`](configuration.md#env_key_stores).

## Models

- **`SimpleTeam`** has one field, `name`. It is encrypted under the system silo's
  keys, so it reads in the site-wide admin with no team in context. Names are
  unique without regard to case: "Acme" and "acme" cannot both exist.
- **`SimpleTeamMembership`** joins one user to one team. It is a one-to-one
  relation to the user, so the database refuses a second team for the same user
  and the middleware never has to choose between two.

The silo UID of a team is `simpleteam-{pk}`. A surrogate key is never reissued, so
a deleted team's UID never names a new team.

A model holding a team's data should point at the team with `PROTECT`:

```python
team = models.ForeignKey(SimpleTeam, on_delete=models.PROTECT)
```

Then a team cannot be deleted from under rows that need its keys.

## The middleware

`SimpleTeamSiloMiddleware` goes below `AuthenticationMiddleware`, which sets
`request.user`. On each authenticated request it reads the user's membership, at
the cost of one query, and makes that team the current silo for the request. A
user with no team, and an anonymous user, get no silo, so encrypted access fails as
it does under any adapter with nothing current.

Outside a request, such as in a shell or a task, set the silo yourself. See
[Silo context](encrypted-data.md#silo-context).

## Managing teams in the admin

The app registers one admin, **Simple teams**, under the app's section of the
Django admin. Staff need the add, change, and delete permissions on Simple teams
and on Simple team memberships to use every action below.

- **Add a team.** Choose **Add simple team**, enter the name, and save. The
  membership table on the same page adds members at the same time.
- **Add a member.** In the **Simple team memberships** table on the team's page,
  choose a user and save. The user must already exist; create users first, under
  **Users**. Use the extra blank row, or **Add another Simple team
  membership**. The user's next request runs with this team as the current silo.
- **Move a user to another team.** Remove the user from the first team's table
  (tick **Delete** on the row and save), then add the user to the second team. A
  user already in a team cannot be added to another: the admin reports that a
  membership for this user already exists.
- **Rename a team.** Change the name and save. The silo UID is built from the
  primary key, so a rename does not move the team's keys.
- **Delete a team.** Deleting a team also deletes its memberships and leaves the
  users. If any model points at the team with `PROTECT`, the admin lists those
  rows and refuses the delete until they are gone.
- **Search teams.** The search box matches any part of a name, ignoring case. A
  blind index answers only whether two whole names are equal, so the admin
  decrypts every name in memory on each search. That suits the number of teams this
  app is built for; with tens of thousands it becomes noticeable.

The key pages for a team's data keys are the same as for any silo: see
[Using the admin panel](admin-panel.md).

## Keys

A team's keys are created on its first encrypted write, under the default
[`KEY_AUTO_PROVISION`](configuration.md#key_auto_provision). To create them when
the team is saved instead, or with `KEY_AUTO_PROVISION` off, list the model in
[`SILO_AUTO_KEY_CREATION`](configuration.md#silo_auto_key_creation). Deleting a
team does not schedule its keys for deletion unless you list it in
[`SILO_AUTO_KEY_DELETION`](configuration.md#silo_auto_key_deletion):

```python
ENCRYPTION = {
    # ...
    "SILO_AUTO_KEY_CREATION": ["default"],
    "SILO_AUTO_KEY_DELETION": ["default"],
}
```

## Moving off the app

To move to another silo adapter, configure it and keep the app installed until the
data has moved. The package raises no error for that combination.
