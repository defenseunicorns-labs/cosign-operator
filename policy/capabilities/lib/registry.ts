/**
 * Minimal OCI Distribution API client for fetching cosign signature artifacts.
 */

export interface RegistryConfig {
  /** Use HTTP instead of HTTPS */
  allowHttp?: boolean;
  /** Basic auth username */
  username?: string;
  /** Basic auth password */
  password?: string;
}

function baseUrl(registry: string, config: RegistryConfig): string {
  const scheme = config.allowHttp ? "http" : "https";
  return `${scheme}://${registry}`;
}

function authHeaders(config: RegistryConfig): Record<string, string> {
  if (config.username && config.password) {
    const encoded = Buffer.from(
      `${config.username}:${config.password}`,
    ).toString("base64");
    return { Authorization: `Basic ${encoded}` };
  }
  return {};
}

/**
 * Resolve an image tag to its digest via HEAD request.
 * Returns the digest string (e.g., "sha256:abc123...").
 */
export async function resolveDigest(
  registry: string,
  repo: string,
  tag: string,
  config: RegistryConfig = {},
): Promise<string> {
  const url = `${baseUrl(registry, config)}/v2/${repo}/manifests/${tag}`;
  const resp = await fetch(url, {
    method: "HEAD",
    headers: {
      ...authHeaders(config),
      Accept: [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
      ].join(", "),
    },
  });

  if (!resp.ok) {
    throw new Error(
      `Failed to resolve digest for ${repo}:${tag}: ${resp.status} ${resp.statusText}`,
    );
  }

  const digest = resp.headers.get("docker-content-digest");
  if (!digest) {
    throw new Error(`No Docker-Content-Digest header for ${repo}:${tag}`);
  }
  return digest;
}

/**
 * Fetch an OCI manifest by tag or digest.
 */
export async function getManifest(
  registry: string,
  repo: string,
  reference: string,
  config: RegistryConfig = {},
): Promise<OciManifest> {
  const url = `${baseUrl(registry, config)}/v2/${repo}/manifests/${reference}`;
  console.log(`[registry] getManifest url=${url} auth=${!!config.username}`);
  let resp: Response;
  try {
    resp = await fetch(url, {
      headers: {
        ...authHeaders(config),
        Accept: [
          "application/vnd.oci.image.manifest.v1+json",
          "application/vnd.docker.distribution.manifest.v2+json",
        ].join(", "),
      },
    });
  } catch (err) {
    throw new Error(`Failed to fetch manifest ${repo}:${reference}: ${err}`);
  }


  console.log(`[registry] getManifest status=${resp.status} ${resp.statusText}`);
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(
      `Failed to fetch manifest ${repo}:${reference}: ${resp.status} ${resp.statusText} url=${url} body=${body}`,
    );
  }

  return (await resp.json()) as OciManifest;
}

/**
 * Fetch a blob by digest, returning the raw bytes as a Buffer.
 */
export async function getBlob(
  registry: string,
  repo: string,
  digest: string,
  config: RegistryConfig = {},
): Promise<Buffer> {
  const url = `${baseUrl(registry, config)}/v2/${repo}/blobs/${digest}`;
  const resp = await fetch(url, {
    headers: authHeaders(config),
  });

  if (!resp.ok) {
    throw new Error(
      `Failed to fetch blob ${repo}@${digest}: ${resp.status} ${resp.statusText}`,
    );
  }

  return Buffer.from(await resp.arrayBuffer());
}

/** Minimal OCI manifest types for what we need. */
export interface OciManifest {
  schemaVersion: number;
  mediaType?: string;
  config: { mediaType: string; size: number; digest: string };
  layers: OciLayer[];
}

export interface OciLayer {
  mediaType: string;
  size: number;
  digest: string;
  annotations?: Record<string, string>;
}
