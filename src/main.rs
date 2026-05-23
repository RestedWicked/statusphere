mod ratproto;

use std::str::FromStr;

use color_eyre::eyre::eyre;
use maud::{Markup, html};
use poem::{Route, Server, get, handler, listener::TcpListener, post, web::Form};
use ratproto::{Did, Handle};
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct LoginForm {
    handle: String,
}

fn login_form() -> Markup {
    html! {
        form action="/login" method="post" class="login-form" hx-target="#login-result" {
            input type="text" name="handle" placeholder="Enter your handle (eg alice.bsky.socail)" required;
            button hx-post="/login" { "Log in"}
            p id="login-result" { }
        }
    }
}

fn login_err(err: color_eyre::Result<()>) -> Markup {
    let err = err.unwrap_err();
    html! {
        p { (err) }
    }
}

fn login_success(did: Did) -> Markup {
    html! {
        p { "DID=" (did) }
    }
}

#[handler]
fn index() -> Markup {
    println!("We are indexing here :3");
    html! {
        script src="https://unpkg.com/htmx.org@2.0.4" {}
        body {
            (login_form())
        }

    }
}

#[handler]
fn login(Form(LoginForm { handle }): Form<LoginForm>) -> Markup {
    println!("We are initiating login :3");
    let Ok(handle) = Handle::from_str(&handle) else {
        return login_err(Err(eyre!("Invalid Handle")));
    };
    println!("We got a handle here :3");

    let Ok(did) = handle.resolve() else {
        return login_err(Err(eyre!("Invalid Handle")));
    };

    println!("We have resolved this handle :3");
    let Ok(doc) = did.resolve() else {
        return login_err(Err(eyre!("Invalid Handle")));
    };

    if doc.match_handle(handle) {
        return login_success(did);
    }

    login_err(Err(eyre!("Invalid Handle")))
}

#[tokio::main]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let app = Route::new().at("/", get(index)).at("/login", post(login));

    Server::new(TcpListener::bind("0.0.0.0:3000"))
        .run(app)
        .await?;

    Ok(())
}
