create table "user" (
    id uuid not null,
    email text not null,
    first_name text,
    last_name text,
    instagram text,
    phone text,
    "work" text,
    hashed_password text,
    reset_key text,

    constraint user_pkey primary key (id)
);

create unique index "user_email_key" on "user"("email");

---- create above / drop below ----

drop table "user";
drop index "user_email_key";
