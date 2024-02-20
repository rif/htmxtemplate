CREATE TABLE session (
    id UUID NOT NULL,
    email TEXT NOT NULL,
    group TEXT,
    code TEXT,
    hashed_password TEXT,
    registration_key TEXT,
    reset_password_key TEXT,

    CONSTRAINT user_pkey PRIMARY KEY (id)
);

CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

---- create above / drop below ----

drop table "user";
drop index "user_email_key";
