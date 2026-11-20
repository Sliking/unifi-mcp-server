import { describe, expect, it } from "vitest";
import { assertAllowedPath, UnifiApi, UnifiError } from "../src/unifi/client";

function fakeFetcher(handler: (req: Request) => Response | Promise<Response>) {
	const calls: Request[] = [];
	const fetcher = {
		fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
			const req = new Request(input, init);
			calls.push(req);
			return handler(req);
		},
	} as unknown as Fetcher;
	return { fetcher, calls };
}

describe("UnifiApi", () => {
	it("refuses plain HTTP without a VPC binding", () => {
		expect(() => new UnifiApi({ baseUrl: "http://192.168.1.1", apiKey: "k" })).toThrow(UnifiError);
	});

	it("requires an API key", () => {
		expect(() => new UnifiApi({ baseUrl: "https://192.168.1.1", apiKey: "" })).toThrow(UnifiError);
	});

	it("sends authenticated GET requests through the VPC binding and unwraps legacy responses", async () => {
		const { fetcher, calls } = fakeFetcher(() => Response.json({ meta: { rc: "ok" }, data: [{ _id: "n1", name: "LAN" }] }));
		const api = new UnifiApi({ baseUrl: "https://192.168.1.1", apiKey: "secret", vpc: fetcher, accessClientId: "id", accessClientSecret: "s" });
		const nets = await api.networks("default");
		expect(nets).toEqual([{ _id: "n1", name: "LAN" }]);
		expect(calls[0].method).toBe("GET");
		expect(new URL(calls[0].url).pathname).toBe("/proxy/network/api/s/default/rest/networkconf");
		expect(calls[0].headers.get("X-API-KEY")).toBe("secret");
		expect(calls[0].headers.get("CF-Access-Client-Id")).toBe("id");
	});

	it("memoises identical requests", async () => {
		const { fetcher, calls } = fakeFetcher(() => Response.json({ data: [] }));
		const api = new UnifiApi({ baseUrl: "https://u", apiKey: "k", vpc: fetcher });
		await Promise.all([api.clients("default"), api.clients("default")]);
		expect(calls).toHaveLength(1);
	});

	it("treats missing optional endpoints as empty", async () => {
		const { fetcher } = fakeFetcher(() => new Response("nope", { status: 404 }));
		const api = new UnifiApi({ baseUrl: "https://u", apiKey: "k", vpc: fetcher });
		expect(await api.zones("default")).toEqual([]);
		await expect(api.clients("default")).rejects.toThrow(/not available/);
	});

	it("maps auth failures and redirects to clear errors without leaking the key", async () => {
		const { fetcher } = fakeFetcher(() => new Response(null, { status: 302, headers: { Location: "https://x.cloudflareaccess.com" } }));
		const api = new UnifiApi({ baseUrl: "https://u", apiKey: "topsecret", vpc: fetcher });
		const err = await api.devices("default").catch((e) => e);
		expect(err).toBeInstanceOf(UnifiError);
		expect(String(err.message)).not.toContain("topsecret");
	});

	it("rejects invalid site names (path injection)", async () => {
		const { fetcher, calls } = fakeFetcher(() => Response.json({ data: [] }));
		const api = new UnifiApi({ baseUrl: "https://u", apiKey: "k", vpc: fetcher });
		await expect(api.clients("../../api/auth")).rejects.toThrow(/Invalid site/);
		expect(calls).toHaveLength(0);
	});

	it("only permits allow-listed read endpoints", () => {
		expect(() => assertAllowedPath("/proxy/network/api/s/default/cmd/devmgr")).toThrow();
		expect(() => assertAllowedPath("/api/auth/login")).toThrow();
		expect(() => assertAllowedPath("/proxy/network/api/s/default/stat/sta")).not.toThrow();
	});
});
