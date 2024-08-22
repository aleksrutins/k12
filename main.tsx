import { Hono } from "@hono/hono";
import { jwtVerify } from "jose";

type BBClaims = {
	uid: string;
	hid: string;
	post_url: string;
};

const secretKey = new TextEncoder().encode(Deno.env.get("SECRET_KEY")!),
	issuer = Deno.env.get("ISSUER_DOMAIN")!,
	tokenName = Deno.env.get("TOKEN_NAME")!,
	audience = Deno.env.get("AUDIENCE_DOMAIN")!,
	ssoPath = Deno.env.get("SSO_PATH");

const app = new Hono();

app.get("/", async (c) => {
	const token = c.req.param(tokenName)!;

	try {
		const { payload, protectedHeader } = await jwtVerify<BBClaims>(
			token,
			secretKey,
			{
				issuer,
				audience,
			},
		);

		// safe to log in

		const keys = await crypto.subtle.digest(
			"SHA-256",
			new TextEncoder().encode(secretKey + token),
		);
		const uri = payload.post_url;
		const postData = { key: keys, jwt: token };
		const response = await (await fetch(uri, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"User-Agent": "Blackbaud SSO DEMO/ 1.0",
			},
			body: JSON.stringify(postData),
		})).json();

		return c.html(
			<div>
				<h6>Token-Based API Request</h6>
				<ul class="list-group">
					<li class="list-group-item">
						<strong>URL</strong>: {uri}
					</li>
					<li class="list-group-item">
						<strong>Post Data:</strong>
						<pre><code>
						{JSON.stringify(postData)}
						</code></pre>
						<li class="list-group-item">
							<strong>Response Data:</strong>
							<pre><code>{JSON.stringify(response)}</code></pre>
						</li>
					</li>
				</ul>
			</div>,
		);
	} catch (e) {
		return c.html(
			<div role="alert">
				Invalid token or API call failed

				<pre><code>{e.toString()}</code></pre>

				It's possible that you may not have a token - try again:{" "}
				<a href={issuer + ssoPath}>{issuer + ssoPath}</a>
			</div>,
			403,
		);
	}
});

export default app;
