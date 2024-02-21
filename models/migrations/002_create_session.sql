create table session (
    id uuid not null,
    email text not null,
    "group" text,

    constraint session_pkey primary key (id)
);

create table key (
    email text not null,
    "value" text not null,
    desacription text,

    constraint key_pkey primary key (email)
);

alter table "user" add column "group" text;

---- create above / drop below ----

drop table "session";
drop table "key";
alter table "user" drop column "group" text;
