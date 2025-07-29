// Mapping utilities to convert the /config_dump response into the LocalConfig TypeScript object tree.
import {
  Bind,
  Backend,
  Listener,
  LocalConfig,
  Route,
  TcpRoute,
  ListenerProtocol,
  TcpPolicies,
  Policies,
  Match,
  TlsConfig,
  ServiceBackend,
  HostBackend,
  DynamicBackend,
  McpBackend,
  McpTarget,
  TargetFilter,
  StdioTarget,
  SseTarget,
  OpenApiTarget,
  McpConnectionTarget,
  AiBackend,
  TcpBackend,
  TcpBackendRef,
  HeaderModifier,
  RequestRedirect,
  UrlRewrite,
  RequestMirror,
  DirectResponse,
  CorsPolicy,
  BackendTLS,
  BackendAuth,
  JwtAuth,
  TimeoutPolicy,
  RetryPolicy,
  McpAuthorization,
  McpAuthentication,
  AuthorityRewrite,
  PathRewrite,
  BackendRef,
} from "./types";

/*
 * Public entry
 */
export function configDumpToLocalConfig(configDump: any): LocalConfig {
  const localConfig: LocalConfig = {
    binds: [],
    workloads: configDump.workloads || [],
    services: configDump.services || [],
  };

  const backends = (configDump.backends || []).map((b: any) => mapToBackend(b)).filter(Boolean);

  localConfig.binds = (configDump.binds || []).map((bind: any) =>
    mapToBind(bind, backends as Backend[])
  );

  return localConfig;
}

/*
 * Bind / Listener / Route
 */
function mapToBind(bindData: any, backends: Backend[]): Bind {
  return {
    port: parseInt(bindData.key.split("/")[1], 10),
    listeners: Object.values(bindData.listeners || {}).map((listenerData: any) =>
      mapToListener(listenerData, backends)
    ),
  };
}

function mapToListener(listenerData: any, backends: Backend[]): Listener {
  return {
    name: listenerData.name,
    gatewayName: listenerData.gatewayName,
    hostname: listenerData.hostname,
    protocol: listenerData.protocol as ListenerProtocol,
    tls: mapToTlsConfig(listenerData.tls),
    routes: Object.values(listenerData.routes || {}).map((routeData: any) =>
      mapToRoute(routeData, backends)
    ),
    tcpRoutes: Object.values(listenerData.tcpRoutes || {}).map((tcpRouteData: any) =>
      mapToTcpRoute(tcpRouteData)
    ),
  };
}

function mapToRoute(routeData: any, backends: Backend[]): Route {
  return {
    name: routeData.routeName,
    ruleName: routeData.ruleName || "",
    hostnames: routeData.hostnames || [],
    matches: mapToMatches(routeData.matches),
    policies: mapToPolicies(routeData.policies),
    backends: (routeData.backends || []).map((rb: any) => mapToRouteBackend(rb, backends)),
  };
}

function mapToTcpRoute(tcpRouteData: any): TcpRoute {
  return {
    name: tcpRouteData.routeName,
    ruleName: tcpRouteData.ruleName || "",
    hostnames: tcpRouteData.hostnames || [],
    policies: mapToTcpPolicies(tcpRouteData.policies),
    backends: (tcpRouteData.backends || []).map(mapToTcpBackend),
  };
}

function mapToMatches(matchesData: any): Match[] {
  if (!matchesData) return [];
  return Object.values(matchesData).map((matchData: any) => {
    const match: Match = { path: {} } as Match;

    if (matchData.headers) {
      match.headers = Object.entries(matchData.headers).map(([name, value]) => ({
        name,
        value: { exact: value as string },
      }));
    }

    if (matchData.path) {
      if (matchData.path.exact) {
        match.path.exact = matchData.path.exact;
      } else if (matchData.path.prefix) {
        match.path.pathPrefix = matchData.path.prefix;
      } else if (matchData.path.regex) {
        match.path.regex = [matchData.path.regex, 0];
      }
    }

    if (matchData.method) match.method = { method: matchData.method };

    if (matchData.query) {
      match.query = Object.entries(matchData.query).map(([name, value]) => ({
        name,
        value: { exact: value as string },
      }));
    }

    return match;
  });
}

/*
 * Policy helpers
 */
function mapToPolicies(policiesData: any): Policies | undefined {
  if (!policiesData) return undefined;
  const p: Policies = {} as Policies;

  if (policiesData.request_header_modifier)
    p.requestHeaderModifier = mapToHeaderModifier(policiesData.request_header_modifier);
  if (policiesData.response_header_modifier)
    p.responseHeaderModifier = mapToHeaderModifier(policiesData.response_header_modifier);
  if (policiesData.request_redirect || policiesData.redirect)
    p.requestRedirect = mapToRequestRedirect(
      policiesData.request_redirect ?? policiesData.redirect
    );
  if (policiesData.url_rewrite || policiesData.rewrite)
    p.urlRewrite = mapToUrlRewrite(policiesData.url_rewrite ?? policiesData.rewrite);
  if (policiesData.request_mirror || policiesData.mirror)
    p.requestMirror = mapToRequestMirror(policiesData.request_mirror ?? policiesData.mirror);
  if (policiesData.direct_response)
    p.directResponse = mapToDirectResponse(policiesData.direct_response);
  if (policiesData.cors) p.cors = mapToCorsPolicy(policiesData.cors);
  if (policiesData.mcp_authorization)
    p.mcpAuthorization = mapToMcpAuthorization(policiesData.mcp_authorization);
  if (policiesData.mcp_authentication)
    p.mcpAuthentication = mapToMcpAuthentication(policiesData.mcp_authentication);
  if (policiesData.a2a) p.a2a = policiesData.a2a;
  if (policiesData.ai) p.ai = policiesData.ai;
  if (policiesData.backend_tls) p.backendTLS = mapToBackendTLS(policiesData.backend_tls);
  if (policiesData.backend_auth) p.backendAuth = mapToBackendAuth(policiesData.backend_auth);
  if (policiesData.local_rate_limit) p.localRateLimit = policiesData.local_rate_limit;
  if (policiesData.remote_rate_limit) p.remoteRateLimit = policiesData.remote_rate_limit;
  if (policiesData.jwt) p.jwtAuth = mapToJwtAuth(policiesData.jwt);
  if (policiesData.ext_authz) p.extAuthz = mapToExtAuthz(policiesData.ext_authz);
  if (policiesData.timeout) p.timeout = mapToTimeoutPolicy(policiesData.timeout);
  if (policiesData.retry) p.retry = mapToRetryPolicy(policiesData.retry);

  return p;
}

function mapToTcpPolicies(data: any): TcpPolicies | undefined {
  if (!data) return undefined;
  const tp: TcpPolicies = {};
  if (data.backend_tls) tp.backendTls = mapToBackendTLS(data.backend_tls);
  return tp;
}

/*
 * Backend helpers
 */
function mapToBackend(backendData: any): Backend | undefined {
  if (!backendData || typeof backendData !== "object") return undefined;
  const backend: Backend = {} as Backend;
  if (typeof backendData.weight === "number") backend.weight = backendData.weight;
  if (Array.isArray(backendData.filters)) backend.filters = backendData.filters.map(mapToFilter);
  if (backendData.service) backend.service = mapToServiceBackend(backendData.service);
  else if (backendData.host) backend.host = mapToHostBackend(backendData.host);
  else if (backendData.dynamic) backend.dynamic = {} as DynamicBackend;
  else if (backendData.mcp) backend.mcp = mapToMcpBackend(backendData.mcp);
  else if (backendData.ai) backend.ai = mapToAiBackend(backendData.ai);
  else return undefined;
  return backend;
}

function mapToTcpBackend(tcpBackendData: any): TcpBackend {
  const backendRefData = tcpBackendData.backend ?? tcpBackendData;
  const tcpBackend: TcpBackend = {
    weight: typeof tcpBackendData.weight === "number" ? tcpBackendData.weight : undefined,
    backend: mapToTcpBackendRef(backendRefData),
  };
  return tcpBackend;
}

function mapToTcpBackendRef(data: any): TcpBackendRef {
  const ref: TcpBackendRef = {} as TcpBackendRef;
  if (data?.service) {
    const svc = mapToServiceBackend(data.service);
    if (svc) ref.service = svc;
  }
  if (data?.host) {
    const host = mapToHostBackend(data.host);
    if (host) ref.host = host;
  }
  return ref;
}

function mapToRouteBackend(rb: any, backends: Backend[]): Backend | undefined {
  return backends.find((b) => getBackendName(b) === rb.backend);
}

function getBackendName(backend: Backend): string {
  if (backend.service)
    return `${backend.service.name.namespace}/${backend.service.name.hostname}:${backend.service.port}`;
  if (backend.host) return `${backend.host.Address}:${backend.host.Hostname}`;
  if (backend.mcp) return backend.mcp.name;
  if (backend.ai) return backend.ai.name;
  return "";
}

/*
 * Filter helpers
 */
function mapToFilter(data: any): any {
  const filter: any = {};
  if (!data || typeof data !== "object") return filter;
  if (data.request_header_modifier)
    filter.requestHeaderModifier = mapToHeaderModifier(data.request_header_modifier);
  if (data.response_header_modifier)
    filter.responseHeaderModifier = mapToHeaderModifier(data.response_header_modifier);
  if (data.request_redirect || data.redirect)
    filter.requestRedirect = mapToRequestRedirect(data.request_redirect ?? data.redirect);
  if (data.url_rewrite || data.rewrite)
    filter.urlRewrite = mapToUrlRewrite(data.url_rewrite ?? data.rewrite);
  if (data.request_mirror || data.mirror)
    filter.requestMirror = mapToRequestMirror(data.request_mirror ?? data.mirror);
  if (data.direct_response) filter.directResponse = mapToDirectResponse(data.direct_response);
  if (data.cors) filter.cors = mapToCorsPolicy(data.cors);
  return filter;
}

/*
 * Leaf mappers (service, host, tls, etc.) -----------------------------------------
 */
function mapToServiceBackend(data: any): ServiceBackend | undefined {
  if (!data?.name || typeof data.port !== "number") return undefined;
  return {
    name: { namespace: data.name.namespace, hostname: data.name.hostname },
    port: data.port,
  } as ServiceBackend;
}

function mapToHostBackend(data: any): HostBackend | undefined {
  if (!data) return undefined;
  return {
    Address: typeof data.Address === "string" ? data.Address : undefined,
    Hostname:
      Array.isArray(data.Hostname) && data.Hostname.length === 2
        ? [String(data.Hostname[0]), Number(data.Hostname[1])]
        : undefined,
  } as HostBackend;
}

function mapToDynamicBackend(_: any): DynamicBackend {
  return {} as DynamicBackend;
}

function mapToMcpBackend(data: any): McpBackend | undefined {
  if (typeof data?.name !== "string" || !Array.isArray(data?.target?.targets)) return undefined;
  const targets = data.target.targets.map(mapToMcpTarget).filter(Boolean) as McpTarget[];
  return { name: data.name, targets } as McpBackend;
}

function mapToMcpTarget(data: any): McpTarget | undefined {
  if (!data || typeof data.name !== "string") return undefined;
  const target: McpTarget = { name: data.name } as McpTarget;
  if (Array.isArray(data.filters))
    target.filters = data.filters.map(mapToTargetFilter).filter(Boolean);
  if (data.stdio) target.stdio = mapToStdioTarget(data.stdio);
  else if (data.sse) target.sse = mapToSseTarget(data.sse);
  else if (data.openapi) target.openapi = mapToOpenApiTarget(data.openapi);
  else if (data.mcp) target.mcp = mapToMcpConnectionTarget(data.mcp);
  return target;
}

function mapToTargetFilter(data: any): TargetFilter | undefined {
  if (!data || typeof data.matcher !== "string") return undefined;
  return { matcher: data.matcher, resource_type: data.resource_type };
}

function mapToStdioTarget(data: any): StdioTarget | undefined {
  if (!data || typeof data.cmd !== "string") return undefined;
  return { cmd: data.cmd, args: data.args, env: data.env } as StdioTarget;
}

function mapToSseTarget(data: any): SseTarget | undefined {
  if (!data || typeof data.host !== "string" || typeof data.port !== "number") return undefined;
  return { host: data.host, port: data.port, path: data.path } as SseTarget;
}

function mapToOpenApiTarget(data: any): OpenApiTarget | undefined {
  if (!data || typeof data.host !== "string" || typeof data.port !== "number") return undefined;
  return { host: data.host, port: data.port, schema: data.schema } as OpenApiTarget;
}

function mapToMcpConnectionTarget(data: any): McpConnectionTarget | undefined {
  if (!data || typeof data.host !== "string" || typeof data.port !== "number") return undefined;
  return { host: data.host, port: data.port, path: data.path } as McpConnectionTarget;
}

function mapToAiBackend(data: any): AiBackend | undefined {
  if (!data?.name || !data.provider) return undefined;
  return {
    name: data.name,
    provider: data.provider,
    hostOverride: data.hostOverride ? mapToHostBackend(data.hostOverride) : undefined,
  } as AiBackend;
}

function mapToTlsConfig(data: any): TlsConfig | undefined {
  if (!data) return undefined;
  return { cert: data.cert, key: data.key } as TlsConfig;
}

/*
 * Sub-helpers for modifiers, redirects, TLS, etc.
 */
function mapToHeaderModifier(data: any): HeaderModifier | undefined {
  if (!data || typeof data !== "object") return undefined;
  const mod: HeaderModifier = {} as HeaderModifier;
  if (data.add && typeof data.add === "object")
    mod.add = Object.entries(data.add) as [string, string][];
  if (data.set && typeof data.set === "object")
    mod.set = Object.entries(data.set) as [string, string][];
  if (Array.isArray(data.remove)) mod.remove = data.remove;
  return Object.keys(mod).length ? mod : undefined;
}

function mapToAuthorityRewrite(data: any): AuthorityRewrite | undefined {
  if (!data || typeof data !== "object") return undefined;
  const ar: AuthorityRewrite = {} as AuthorityRewrite;
  if (typeof data.full === "string") ar.full = data.full;
  if (typeof data.host === "string") ar.host = data.host;
  if (typeof data.port === "number") ar.port = data.port;
  return ar;
}

function mapToPathRewrite(data: any): PathRewrite | undefined {
  if (!data || typeof data !== "object") return undefined;
  const pr: PathRewrite = {} as PathRewrite;
  if (typeof data.full === "string") pr.full = data.full;
  if (typeof data.prefix === "string") pr.prefix = data.prefix;
  return pr;
}

function mapToRequestRedirect(data: any): RequestRedirect | undefined {
  if (!data || typeof data !== "object") return undefined;
  const rr: RequestRedirect = {} as RequestRedirect;
  if (typeof data.scheme === "string") rr.scheme = data.scheme;
  if (data.authority) rr.authority = mapToAuthorityRewrite(data.authority) ?? null;
  if (data.path) rr.path = mapToPathRewrite(data.path) ?? null;
  if (typeof data.status === "number") rr.status = data.status;
  return rr;
}

function mapToUrlRewrite(data: any): UrlRewrite | undefined {
  if (!data || typeof data !== "object") return undefined;
  const ur: UrlRewrite = {} as UrlRewrite;
  if (data.authority) ur.authority = mapToAuthorityRewrite(data.authority) ?? null;
  if (data.path) ur.path = mapToPathRewrite(data.path) ?? null;
  return ur;
}

function mapToBackendRef(data: any): BackendRef | undefined {
  if (!data || typeof data !== "object") return undefined;
  const ref: BackendRef = {} as BackendRef;
  if (data.service) {
    const svc = mapToServiceBackend(data.service);
    if (svc) ref.service = svc;
  } else if (data.host) {
    const host = mapToHostBackend(data);
    if (host) ref.host = host;
  }
  return ref;
}

function mapToRequestMirror(data: any): RequestMirror | undefined {
  if (!data || typeof data !== "object") return undefined;
  const backend = mapToBackendRef(data.backend);
  if (!backend) return undefined;
  return {
    backend,
    percentage: typeof data.percentage === "number" ? data.percentage : 100,
  } as RequestMirror;
}

function mapToDirectResponse(data: any): DirectResponse | undefined {
  if (!data || typeof data !== "object") return undefined;
  return {
    body: data.body,
    status: typeof data.status === "number" ? data.status : 200,
  } as DirectResponse;
}

function mapToCorsPolicy(data: any): CorsPolicy | undefined {
  if (!data || typeof data !== "object") return undefined;
  const cp: CorsPolicy = {} as CorsPolicy;
  if (typeof data.allowCredentials === "boolean") cp.allowCredentials = data.allowCredentials;
  if (Array.isArray(data.allowHeaders)) cp.allowHeaders = data.allowHeaders;
  if (Array.isArray(data.allowMethods)) cp.allowMethods = data.allowMethods;
  if (Array.isArray(data.allowOrigins)) cp.allowOrigins = data.allowOrigins;
  if (Array.isArray(data.exposeHeaders)) cp.exposeHeaders = data.exposeHeaders;
  if (typeof data.maxAge === "string" || data.maxAge === null) cp.maxAge = data.maxAge;
  return cp;
}

function mapToMcpAuthorization(data: any): McpAuthorization | undefined {
  if (!data || typeof data !== "object" || !Array.isArray(data.rules)) return undefined;
  return { rules: data.rules } as McpAuthorization;
}

function mapToMcpAuthentication(data: any): McpAuthentication | undefined {
  if (!data || typeof data !== "object") return undefined;
  return {
    issuer: String(data.issuer ?? ""),
    scopes: Array.isArray(data.scopes) ? data.scopes : [],
    provider: data.provider as any,
  } as McpAuthentication;
}

function mapToBackendTLS(data: any): BackendTLS | undefined {
  if (!data || typeof data !== "object") return undefined;
  return {
    cert: data.cert ?? null,
    key: data.key ?? null,
    root: data.root ?? null,
    insecure: !!data.insecure,
    insecureHost: !!data.insecureHost,
  } as BackendTLS;
}

function mapToBackendAuth(data: any): BackendAuth | undefined {
  if (!data || typeof data !== "object") return undefined;
  const auth: BackendAuth = {} as BackendAuth;
  if (data.passthrough) auth.passthrough = data.passthrough;
  if (data.key) auth.key = data.key;
  if (data.gcp) auth.gcp = data.gcp;
  if (data.aws) auth.aws = data.aws;
  return auth;
}

function mapToJwtAuth(data: any): JwtAuth | undefined {
  if (!data || typeof data !== "object") return undefined;
  return {
    issuer: String(data.issuer ?? ""),
    audiences: Array.isArray(data.audiences) ? data.audiences : [],
    jwks: data.jwks,
  } as JwtAuth;
}

function mapToExtAuthz(data: any): any {
  if (!data || typeof data !== "object") return undefined;
  return data;
}

function mapToTimeoutPolicy(data: any): TimeoutPolicy | undefined {
  if (!data || typeof data !== "object") return undefined;
  return {
    requestTimeout: data.requestTimeout ?? null,
    backendRequestTimeout: data.backendRequestTimeout ?? null,
  } as TimeoutPolicy;
}

function mapToRetryPolicy(data: any): RetryPolicy | undefined {
  if (!data || typeof data !== "object") return undefined;
  return {
    attempts: typeof data.attempts === "number" ? data.attempts : undefined,
    backoff: data.backoff ?? null,
    codes: Array.isArray(data.codes) ? data.codes : [],
  } as RetryPolicy;
}
