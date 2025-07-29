import {
  McpTarget,
  Target,
  Listener,
  LocalConfig,
  Bind,
  Backend,
  Route,
  TcpRoute,
  ListenerProtocol,
  TcpPolicies,
  Policies,
  Match,
  TlsConfig,
  McpBackend,
  ServiceBackend,
  HostBackend,
  DynamicBackend,
  AiBackend,
  Filter,
  TargetFilter,
  StdioTarget,
  SseTarget,
  OpenApiTarget,
  McpConnectionTarget,
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

const API_URL = process.env.NODE_ENV === "production" ? "" : "http://localhost:15000";

export function isXdsMode() {
  return xdsMode;
}

let xdsMode = false;

/**
 * Fetches the full configuration from the agentgateway server
 */
export async function fetchConfig(): Promise<LocalConfig> {
  try {
    const response = await fetch(`${API_URL}/config_dump`);

    if (!response.ok) {
      if (response.status === 500) {
        const errorText = await response.text();
        const error = new Error(`Server configuration error: ${errorText}`);
        (error as any).isConfigurationError = true;
        (error as any).status = 500;
        throw error;
      }

      throw new Error(`Failed to fetch config: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return configDumpToLocalConfig(data);
  } catch (error) {
    console.error("Error fetching config:", error);
    throw error;
  }
}
/**
 * Converts the config_dump response from the agentgateway server to a LocalConfig ts object
 */
export function configDumpToLocalConfig(configDump: any): LocalConfig {
  const localConfig: LocalConfig = {
    binds: [],
    workloads: configDump.workloads || [],
    services: configDump.services || [],
  };

  const backends = (configDump.backends || []).map((b: any) => mapToBackend(b)).filter(Boolean);

  if (configDump.config?.xds?.address) {
    console.log("XDS mode enabled");
    xdsMode = true;
  }

  localConfig.binds = (configDump.binds || []).map((bind: any) => mapToBind(bind, backends));

  return localConfig;
}

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

// Stub mapping for TCP backend structures
function mapToTcpBackend(tcpBackendData: any): TcpBackend {
  // Basic shape conversion – extend as schema details become available
  const backendRefData = tcpBackendData.backend ?? tcpBackendData;

  const tcpBackend: TcpBackend = {
    weight: typeof tcpBackendData.weight === "number" ? tcpBackendData.weight : undefined,
    backend: mapToTcpBackendRef(backendRefData),
  };

  return tcpBackend;
}

function mapToTcpBackendRef(backendRefData: any): TcpBackendRef {
  const ref: TcpBackendRef = {} as TcpBackendRef;

  if (backendRefData?.service) {
    const service = mapToServiceBackend(backendRefData.service);
    if (service) ref.service = service;
  }

  if (backendRefData?.host) {
    const host = mapToHostBackend(backendRefData.host);
    if (host) ref.host = host;
  }

  return ref;
}

function mapToMatches(matchesData: any): Match[] {
  if (!matchesData) return [];

  return Object.values(matchesData).map((matchData: any) => {
    const match: Match = {
      path: {},
    };

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

    if (matchData.method) {
      match.method = { method: matchData.method };
    }

    if (matchData.query) {
      match.query = Object.entries(matchData.query).map(([name, value]) => ({
        name,
        value: { exact: value as string },
      }));
    }

    return match;
  });
}

function mapToPolicies(policiesData: any): Policies | undefined {
  if (!policiesData) return undefined;

  const policies: Policies = {};

  if (policiesData.request_header_modifier) {
    policies.requestHeaderModifier = mapToHeaderModifier(policiesData.request_header_modifier);
  }
  if (policiesData.response_header_modifier) {
    policies.responseHeaderModifier = mapToHeaderModifier(policiesData.response_header_modifier);
  }
  if (policiesData.redirect) {
    policies.requestRedirect = mapToRequestRedirect(policiesData.redirect);
  }
  if (policiesData.rewrite) {
    policies.urlRewrite = mapToUrlRewrite(policiesData.rewrite);
  }
  if (policiesData.mirror) {
    policies.requestMirror = mapToRequestMirror(policiesData.mirror);
  }
  if (policiesData.direct_response) {
    policies.directResponse = mapToDirectResponse(policiesData.direct_response);
  }
  if (policiesData.cors) {
    policies.cors = mapToCorsPolicy(policiesData.cors);
  }
  if (policiesData.mcp_authorization) {
    policies.mcpAuthorization = mapToMcpAuthorization(policiesData.mcp_authorization);
  }
  if (policiesData.mcp_authentication) {
    policies.mcpAuthentication = mapToMcpAuthentication(policiesData.mcp_authentication);
  }
  if (policiesData.a2a) {
    policies.a2a = policiesData.a2a;
  }
  if (policiesData.ai) {
    policies.ai = policiesData.ai;
  }
  if (policiesData.backend_tls) {
    policies.backendTLS = mapToBackendTLS(policiesData.backend_tls);
  }
  if (policiesData.backend_auth) {
    policies.backendAuth = mapToBackendAuth(policiesData.backend_auth);
  }
  if (policiesData.local_rate_limit) {
    policies.localRateLimit = policiesData.local_rate_limit;
  }
  if (policiesData.remote_rate_limit) {
    policies.remoteRateLimit = policiesData.remote_rate_limit;
  }
  if (policiesData.jwt) {
    policies.jwtAuth = mapToJwtAuth(policiesData.jwt);
  }
  if (policiesData.ext_authz) {
    policies.extAuthz = mapToExtAuthz(policiesData.ext_authz);
  }
  if (policiesData.timeout) {
    policies.timeout = mapToTimeoutPolicy(policiesData.timeout);
  }
  if (policiesData.retry) {
    policies.retry = mapToRetryPolicy(policiesData.retry);
  }

  return policies;
}

function mapToTcpPolicies(tcpPoliciesData: any): TcpPolicies | undefined {
  if (!tcpPoliciesData) return undefined;

  const tcpPolicies: TcpPolicies = {};

  if (tcpPoliciesData.backend_tls) {
    tcpPolicies.backendTls = tcpPoliciesData.backend_tls;
  }

  return tcpPolicies;
}

function mapToBackend(backendData: any): Backend | undefined {
  if (!backendData || typeof backendData !== "object") return undefined;

  const backend: Backend = {};

  if (typeof backendData.weight === "number") {
    backend.weight = backendData.weight;
  }

  if (Array.isArray(backendData.filters)) {
    backend.filters = backendData.filters.map(mapToFilter);
  }

  if (backendData.service) {
    const svc = mapToServiceBackend(backendData.service);
    if (svc) backend.service = svc;
  } else if (backendData.host) {
    const host = mapToHostBackend(backendData.host);
    if (host) backend.host = host;
  } else if (backendData.dynamic) {
    backend.dynamic = {}; // dynamic backend has no fields
  } else if (backendData.mcp) {
    const mcp = mapToMcpBackend(backendData.mcp);
    if (mcp) backend.mcp = mcp;
  } else if (backendData.ai) {
    const ai = mapToAiBackend(backendData.ai);
    if (ai) backend.ai = ai;
  } else {
    return undefined;
  }

  return backend;
}

function mapToRouteBackend(routeBackendData: any, backends: Backend[]): Backend | undefined {
  return backends.find((backend) => getBackendName(backend) === routeBackendData.backend);
}

function getBackendName(backendData: Backend): string {
  if (backendData.service) {
    return `${backendData.service.name.namespace}/${backendData.service.name.hostname}:${backendData.service.port}`;
  } else if (backendData.host) {
    return `${backendData.host.Address}:${backendData.host.Hostname}`;
  } else if (backendData.mcp) {
    return backendData.mcp.name;
  } else if (backendData.ai) {
    return backendData.ai.name;
  } else {
    return "";
  }
}

function mapToFilter(filterData: any): Filter {
  const filter: Filter = {};

  if (!filterData || typeof filterData !== "object") return filter;

  if (filterData.request_header_modifier) {
    filter.requestHeaderModifier = mapToHeaderModifier(filterData.request_header_modifier);
  }
  if (filterData.response_header_modifier) {
    filter.responseHeaderModifier = mapToHeaderModifier(filterData.response_header_modifier);
  }
  if (filterData.redirect) {
    filter.requestRedirect = mapToRequestRedirect(filterData.redirect);
  }
  if (filterData.rewrite) {
    filter.urlRewrite = mapToUrlRewrite(filterData.rewrite);
  }
  if (filterData.mirror) {
    filter.requestMirror = mapToRequestMirror(filterData.mirror);
  }
  if (filterData.direct_response) {
    filter.directResponse = mapToDirectResponse(filterData.direct_response);
  }
  if (filterData.cors) {
    filter.cors = mapToCorsPolicy(filterData.cors);
  }

  return filter;
}

function mapToServiceBackend(serviceBackendData: any): ServiceBackend | undefined {
  if (!serviceBackendData?.name || typeof serviceBackendData.port !== "number") return undefined;

  return {
    name: {
      namespace: serviceBackendData.name.namespace,
      hostname: serviceBackendData.name.hostname,
    },
    port: serviceBackendData.port,
  };
}

function mapToHostBackend(hostBackendData: any): HostBackend | undefined {
  if (!hostBackendData) return undefined;

  return {
    Address: typeof hostBackendData.Address === "string" ? hostBackendData.Address : undefined,
    Hostname:
      Array.isArray(hostBackendData.Hostname) && hostBackendData.Hostname.length === 2
        ? [String(hostBackendData.Hostname[0]), Number(hostBackendData.Hostname[1])]
        : undefined,
  };
}

function mapToDynamicBackend(_: any): DynamicBackend {
  // TODO: Implement dynamic backend mapping when the schema is defined
  return {};
}

function mapToMcpBackend(mcpBackendData: any): McpBackend | undefined {
  const name = mcpBackendData?.name;
  const targets = mcpBackendData?.target?.targets;

  if (typeof name !== "string" || !Array.isArray(targets)) return undefined;

  const mcpTargets = targets.map((t: any) => mapToMcpTarget(t)).filter(Boolean);
  if (!mcpTargets) return undefined;

  return {
    name,
    targets: mcpTargets as McpTarget[],
  };
}

function mapToMcpTarget(targetData: any): McpTarget | undefined {
  if (!targetData || typeof targetData.name !== "string") return undefined;

  const target: McpTarget = {
    name: targetData.name,
  };

  if (Array.isArray(targetData.filters)) {
    target.filters = targetData.filters.map((f: any) => mapToTargetFilter(f)).filter(Boolean);
  }

  if (targetData.stdio) {
    const stdio = mapToStdioTarget(targetData.stdio);
    if (stdio) target.stdio = stdio;
  } else if (targetData.sse) {
    const sse = mapToSseTarget(targetData.sse);
    if (sse) target.sse = sse;
  } else if (targetData.openapi) {
    const openapi = mapToOpenApiTarget(targetData.openapi);
    if (openapi) target.openapi = openapi;
  } else if (targetData.mcp) {
    const mcp = mapToMcpConnectionTarget(targetData.mcp);
    if (mcp) target.mcp = mcp;
  }
  return target;
}

function mapToTargetFilter(filterData: any): TargetFilter | undefined {
  if (!filterData || typeof filterData.matcher !== "string") return undefined;

  const filter: TargetFilter = {
    matcher: filterData.matcher,
    resource_type: filterData.resource_type,
  };

  return filter;
}

function mapToStdioTarget(stdioData: any): StdioTarget | undefined {
  if (!stdioData || typeof stdioData.cmd !== "string") return undefined;

  const stdio: StdioTarget = {
    cmd: stdioData.cmd,
  };

  return stdio;
}

function mapToSseTarget(sseData: any): SseTarget | undefined {
  if (!sseData || typeof sseData.host !== "string" || typeof sseData.port !== "number")
    return undefined;

  const sse: SseTarget = {
    host: sseData.host,
    port: sseData.port,
    path: sseData.path,
  };

  return sse;
}

function mapToOpenApiTarget(openapiData: any): OpenApiTarget | undefined {
  if (!openapiData || typeof openapiData.host !== "string" || typeof openapiData.port !== "number")
    return undefined;

  const openapi: OpenApiTarget = {
    host: openapiData.host,
    port: openapiData.port,
    schema: openapiData.schema,
  };

  return openapi;
}

function mapToMcpConnectionTarget(mcpConnectionData: any): McpConnectionTarget | undefined {
  if (
    !mcpConnectionData ||
    typeof mcpConnectionData.host !== "string" ||
    typeof mcpConnectionData.port !== "number"
  )
    return undefined;

  const mcpConnection: McpConnectionTarget = {
    host: mcpConnectionData.host,
    port: mcpConnectionData.port,
    path: mcpConnectionData.path,
  };

  return mcpConnection;
}

function mapToAiBackend(aiBackendData: any): AiBackend | undefined {
  if (!aiBackendData?.name || !aiBackendData.provider) return undefined;

  return {
    name: aiBackendData.name,
    provider: aiBackendData.provider,
    hostOverride: aiBackendData.hostOverride
      ? mapToHostBackend(aiBackendData.hostOverride)
      : undefined,
  };
}

function mapToTlsConfig(tlsData: any): TlsConfig | undefined {
  if (!tlsData) return undefined;

  return {
    cert: tlsData.cert,
    key: tlsData.key,
  };
}

/**
 * Cleans up the configuration by removing empty arrays and undefined values
 */
function cleanupConfig(config: LocalConfig): LocalConfig {
  const cleaned = { ...config };

  // Clean up binds
  cleaned.binds = cleaned.binds.map((bind) => {
    const cleanedBind = { ...bind };

    // Clean up listeners
    cleanedBind.listeners = cleanedBind.listeners.map((listener) => {
      const cleanedListener: any = {
        protocol: listener.protocol,
      };

      // Only include fields that have values
      if (listener.name) cleanedListener.name = listener.name;
      if (listener.gatewayName) cleanedListener.gatewayName = listener.gatewayName;
      if (listener.hostname) cleanedListener.hostname = listener.hostname;
      if (listener.tls) cleanedListener.tls = listener.tls;

      // Include routes if they exist (even if empty)
      if (listener.routes !== undefined && listener.routes !== null) {
        cleanedListener.routes = listener.routes.map((route) => {
          const cleanedRoute: any = {
            hostnames: route.hostnames,
            matches: route.matches,
            backends: route.backends,
          };

          if (route.name) cleanedRoute.name = route.name;
          if (route.ruleName) cleanedRoute.ruleName = route.ruleName;
          if (route.policies) cleanedRoute.policies = route.policies;

          return cleanedRoute;
        });
      }

      // Include tcpRoutes if they exist (even if empty)
      if (listener.tcpRoutes !== undefined && listener.tcpRoutes !== null) {
        cleanedListener.tcpRoutes = listener.tcpRoutes;
      }

      return cleanedListener;
    });

    return cleanedBind;
  });

  // Clean up workloads and services - only include if they have content
  if (cleaned.workloads && cleaned.workloads.length > 0) {
    // Keep workloads as is if they exist
  } else {
    delete (cleaned as any).workloads;
  }

  if (cleaned.services && cleaned.services.length > 0) {
    // Keep services as is if they exist
  } else {
    delete (cleaned as any).services;
  }

  return cleaned;
}

/**
 * Updates the configuration
 */
export async function updateConfig(config: LocalConfig): Promise<void> {
  if (isXdsMode()) {
    throw new Error("Configuration is managed by XDS and cannot be updated via the UI.");
  }
  try {
    // Clean up the config before sending
    const cleanedConfig = cleanupConfig(config);

    const response = await fetch(`${API_URL}/config`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(cleanedConfig),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(
        `Failed to update configuration: ${response.status} ${response.statusText} - ${error}`
      );
    }
  } catch (error) {
    console.error("Error updating configuration:", error);
    throw error;
  }
}

/**
 * Backward compatibility: Fetches all listeners from all binds
 */
export async function fetchListeners(): Promise<Listener[]> {
  try {
    const binds = await fetchBinds();
    const allListeners: Listener[] = [];
    binds.forEach((bind) => {
      allListeners.push(...bind.listeners);
    });
    return allListeners;
  } catch (error) {
    console.error("Error fetching listeners:", error);
    throw error;
  }
}

/**
 * Fetches all MCP targets from the agentgateway server
 */
export async function fetchMcpTargets(): Promise<any[]> {
  try {
    const config = await fetchConfig();
    const mcpTargets: any[] = [];

    config.binds.forEach((bind: Bind) => {
      bind.listeners.forEach((listener: Listener) => {
        listener.routes?.forEach((route: Route) => {
          route.backends.forEach((backend: Backend) => {
            console.log("backend", backend);
            if (backend.mcp) {
              mcpTargets.push(...backend.mcp.targets);
            }
          });
        });
      });
    });

    return mcpTargets;
  } catch (error) {
    console.error("Error fetching MCP targets:", error);
    throw error;
  }
}

/**
 * Fetches all A2A targets from the agentgateway server
 */
export async function fetchA2aTargets(): Promise<any[]> {
  try {
    const config = await fetchConfig();
    const a2aTargets: any[] = [];

    // Extract A2A targets from the configuration
    config.binds.forEach((bind: Bind) => {
      bind.listeners.forEach((listener: Listener) => {
        listener.routes?.forEach((route: Route) => {
          route.backends.forEach((backend: Backend) => {
            if (backend.ai) {
              a2aTargets.push(backend.ai);
            }
          });
        });
      });
    });

    return a2aTargets;
  } catch (error) {
    console.error("Error fetching A2A targets:", error);
    throw error;
  }
}

/**
 * Creates or updates an MCP target on the agentgateway server
 */
export async function createMcpTarget(
  target: Target,
  listenerName?: string,
  port?: number
): Promise<void> {
  try {
    const config = await fetchConfig();

    let targetBind: Bind | null = null;
    let targetListener: Listener | null = null;

    // If port is provided, find the specific bind and listener
    if (port !== undefined && listenerName !== undefined) {
      targetBind = config.binds.find((bind) => bind.port === port) || null;
      if (targetBind) {
        targetListener =
          targetBind.listeners.find((listener) => listener.name === listenerName) || null;
      }
    }

    // If no specific bind/listener found, create default structure
    if (!targetBind) {
      if (config.binds.length === 0) {
        config.binds.push({
          port: port || 8080,
          listeners: [],
        });
      }
      targetBind = config.binds[0];
    }

    if (!targetListener) {
      if (targetBind.listeners.length === 0) {
        const newListener: Listener = {
          protocol: "HTTP" as any,
        };

        // Only set fields that have values
        if (listenerName) {
          newListener.name = listenerName;
        }

        targetBind.listeners.push(newListener);
      }
      targetListener = targetBind.listeners[0];
    }

    // Ensure routes exist
    if (!targetListener.routes) {
      targetListener.routes = [];
    }

    if (targetListener.routes.length === 0) {
      targetListener.routes.push({
        hostnames: [],
        matches: [{ path: { pathPrefix: "/" } }],
        backends: [],
      });
    }

    const route = targetListener.routes[0];

    // Find or create MCP backend
    let mcpBackend = route.backends.find((backend) => backend.mcp);
    if (!mcpBackend) {
      const newMcpBackend: Backend = {
        mcp: {
          name: "mcp-backend",
          targets: [],
        },
      };
      route.backends.push(newMcpBackend);
      mcpBackend = newMcpBackend;
    }

    // Add or update the target
    if (mcpBackend.mcp) {
      const existingIndex = mcpBackend.mcp.targets.findIndex((t) => t.name === target.name);

      // Build target data according to schema - only include fields with values
      const targetData: any = {
        name: target.name,
      };

      // Add the appropriate target type based on what's provided
      if (target.sse) {
        targetData.sse = target.sse;
      } else if (target.mcp) {
        targetData.mcp = target.mcp;
      } else if (target.stdio) {
        targetData.stdio = target.stdio;
      } else if (target.openapi) {
        targetData.openapi = target.openapi;
      }

      if (existingIndex >= 0) {
        mcpBackend.mcp.targets[existingIndex] = targetData;
      } else {
        mcpBackend.mcp.targets.push(targetData);
      }
    }

    await updateConfig(config);
  } catch (error) {
    console.error("Error creating MCP target:", error);
    throw error;
  }
}

/**
 * Creates or updates an A2A target on the agentgateway server
 */
export async function createA2aTarget(
  target: Target,
  listenerName?: string,
  port?: number
): Promise<void> {
  try {
    const config = await fetchConfig();

    let targetBind: Bind | null = null;
    let targetListener: Listener | null = null;

    // If port is provided, find the specific bind and listener
    if (port !== undefined && listenerName !== undefined) {
      targetBind = config.binds.find((bind) => bind.port === port) || null;
      if (targetBind) {
        targetListener =
          targetBind.listeners.find((listener) => listener.name === listenerName) || null;
      }
    }

    // If no specific bind/listener found, create default structure
    if (!targetBind) {
      if (config.binds.length === 0) {
        config.binds.push({
          port: port || 8080,
          listeners: [],
        });
      }
      targetBind = config.binds[0];
    }

    if (!targetListener) {
      if (targetBind.listeners.length === 0) {
        const newListener: Listener = {
          protocol: "HTTP" as any,
        };

        // Only set fields that have values
        if (listenerName) {
          newListener.name = listenerName;
        }

        targetBind.listeners.push(newListener);
      }
      targetListener = targetBind.listeners[0];
    }

    // Ensure routes exist
    if (!targetListener.routes) {
      targetListener.routes = [];
    }

    if (targetListener.routes.length === 0) {
      targetListener.routes.push({
        hostnames: [],
        matches: [{ path: { pathPrefix: "/" } }],
        backends: [],
      });
    }

    const route = targetListener.routes[0];

    // Create or update AI backend
    let aiBackend = route.backends.find((backend) => backend.ai);
    if (!aiBackend) {
      const newAiBackend: Backend = {
        ai: {
          name: target.name,
          provider: {
            openAI: { model: "gpt-4" }, // Default provider
          },
        },
      };

      // Only add hostOverride if a2a target has values
      if (target.a2a) {
        newAiBackend.ai!.hostOverride = {
          Address: target.a2a.host,
          Hostname: [target.a2a.host, target.a2a.port],
        };
      }

      route.backends.push(newAiBackend);
      aiBackend = newAiBackend;
    } else {
      // Update existing AI backend
      if (aiBackend.ai) {
        aiBackend.ai.name = target.name;

        // Only set hostOverride if a2a target has values
        if (target.a2a) {
          aiBackend.ai.hostOverride = {
            Address: target.a2a.host,
            Hostname: [target.a2a.host, target.a2a.port],
          };
        } else {
          // Remove hostOverride if no a2a config
          delete aiBackend.ai.hostOverride;
        }
      }
    }

    await updateConfig(config);
  } catch (error) {
    console.error("Error creating A2A target:", error);
    throw error;
  }
}

/**
 * Updates a single target on the agentgateway server
 */
export async function updateTarget(
  target: Target,
  listenerName?: string,
  port?: number
): Promise<void> {
  try {
    if (target.sse || target.mcp || target.stdio || target.openapi) {
      await createMcpTarget(target, listenerName, port);
    } else if (target.a2a) {
      await createA2aTarget(target, listenerName, port);
    } else {
      throw new Error("Invalid target type");
    }
  } catch (error) {
    console.error("Error updating target:", error);
    throw error;
  }
}

/**
 * Fetches a specific MCP target by name
 */
export async function getMcpTarget(name: string): Promise<any> {
  try {
    const mcpTargets = await fetchMcpTargets();
    const target = mcpTargets.find((t) => t.name === name);

    if (!target) {
      throw new Error(`MCP target '${name}' not found`);
    }

    return target;
  } catch (error) {
    console.error("Error fetching MCP target:", error);
    throw error;
  }
}

/**
 * Fetches a specific A2A target by name
 */
export async function getA2aTarget(name: string): Promise<any> {
  try {
    const a2aTargets = await fetchA2aTargets();
    const target = a2aTargets.find((t) => t.name === name);

    if (!target) {
      throw new Error(`A2A target '${name}' not found`);
    }

    return target;
  } catch (error) {
    console.error("Error fetching A2A target:", error);
    throw error;
  }
}

/**
 * Deletes an MCP target by name
 */
export async function deleteMcpTarget(name: string): Promise<void> {
  try {
    const config = await fetchConfig();

    // Find and remove the target from all MCP backends
    config.binds.forEach((bind: Bind) => {
      bind.listeners.forEach((listener: Listener) => {
        listener.routes?.forEach((route: Route) => {
          route.backends.forEach((backend: Backend) => {
            if (backend.mcp) {
              backend.mcp.targets = backend.mcp.targets.filter((t) => t.name !== name);
            }
          });
        });
      });
    });

    await updateConfig(config);
  } catch (error) {
    console.error("Error deleting MCP target:", error);
    throw error;
  }
}

/**
 * Deletes an A2A target by name
 */
export async function deleteA2aTarget(name: string): Promise<void> {
  try {
    const config = await fetchConfig();

    // Find and remove the A2A backend
    config.binds.forEach((bind: Bind) => {
      bind.listeners.forEach((listener: Listener) => {
        listener.routes?.forEach((route: Route) => {
          route.backends = route.backends.filter(
            (backend) => !backend.ai || backend.ai.name !== name
          );
        });
      });
    });

    await updateConfig(config);
  } catch (error) {
    console.error("Error deleting A2A target:", error);
    throw error;
  }
}

/**
 * Fetches targets associated with a specific listener
 */
export async function fetchListenerTargets(listenerName: string): Promise<any[]> {
  try {
    const config = await fetchConfig();
    const targets: any[] = [];

    config.binds.forEach((bind: Bind) => {
      bind.listeners.forEach((listener: Listener) => {
        if (listener.name === listenerName) {
          listener.routes?.forEach((route: Route) => {
            route.backends.forEach((backend: Backend) => {
              if (backend.mcp) {
                targets.push(...backend.mcp.targets);
              }
              if (backend.ai) {
                targets.push(backend.ai);
              }
            });
          });
        }
      });
    });

    return targets;
  } catch (error) {
    console.error("Error fetching listener targets:", error);
    throw error;
  }
}

/**
 * Fetches a specific listener by name
 */
export async function getListener(name: string): Promise<Listener> {
  try {
    const listeners = await fetchListeners();
    const listener = listeners.find((l) => l.name === name);

    if (!listener) {
      throw new Error(`Listener '${name}' not found`);
    }

    return listener;
  } catch (error) {
    console.error("Error fetching listener:", error);
    throw error;
  }
}

/**
 * Creates or updates a listener on the agentgateway server
 */
export async function createListener(listener: Listener, port?: number): Promise<void> {
  try {
    const config = await fetchConfig();

    // Use provided port or default
    const targetPort = port || 8080;

    // Find or create a bind for the specified port
    let bind = config.binds.find((b) => b.port === targetPort);
    if (!bind) {
      bind = {
        port: targetPort,
        listeners: [],
      };
      config.binds.push(bind);
    }

    // Add or update the listener
    const existingIndex = bind.listeners.findIndex((l) => l.name === listener.name);
    if (existingIndex >= 0) {
      bind.listeners[existingIndex] = listener;
    } else {
      bind.listeners.push(listener);
    }

    await updateConfig(config);
  } catch (error) {
    console.error("Error creating listener:", error);
    throw error;
  }
}

/**
 * Backward compatibility: Adds a listener (wraps addListenerToBind)
 */
export async function addListener(listener: Listener, port: number): Promise<void> {
  return addListenerToBind(listener, port);
}

/**
 * Backward compatibility: Deletes a listener (wraps removeListenerFromBind)
 */
export async function deleteListener(listener: Listener): Promise<void> {
  if (!listener.name) {
    throw new Error("Listener name is required for deletion");
  }
  return removeListenerFromBind(listener.name);
}

/**
 * Deletes all targets and listeners from the agentgateway server
 */
export async function deleteEverything(): Promise<void> {
  try {
    const config = await fetchConfig();

    // Clear all binds (which contain listeners and their targets)
    config.binds = [];

    await updateConfig(config);
  } catch (error) {
    console.error("Error deleting everything:", error);
    throw error;
  }
}

/**
 * Fetches all binds from the agentgateway server
 */
export async function fetchBinds(): Promise<Bind[]> {
  try {
    const config = await fetchConfig();
    return config.binds || [];
  } catch (error) {
    console.error("Error fetching binds:", error);
    throw error;
  }
}

/**
 * Creates a new bind (port binding) on the agentgateway server
 */
export async function createBind(port: number): Promise<void> {
  try {
    const config = await fetchConfig();

    // Check if bind already exists
    const existingBind = config.binds.find((b) => b.port === port);
    if (existingBind) {
      throw new Error(`Bind for port ${port} already exists`);
    }

    // Add new bind
    const newBind: Bind = {
      port,
      listeners: [],
    };

    config.binds.push(newBind);
    await updateConfig(config);
  } catch (error) {
    console.error("Error creating bind:", error);
    throw error;
  }
}

/**
 * Deletes a bind and all its listeners
 */
export async function deleteBind(port: number): Promise<void> {
  try {
    const config = await fetchConfig();

    // Remove the bind
    config.binds = config.binds.filter((bind) => bind.port !== port);

    await updateConfig(config);
  } catch (error) {
    console.error("Error deleting bind:", error);
    throw error;
  }
}

/**
 * Adds a listener to a specific bind
 */
export async function addListenerToBind(listener: Listener, port: number): Promise<void> {
  try {
    const config = await fetchConfig();

    // Find the bind
    let bind = config.binds.find((b) => b.port === port);
    if (!bind) {
      // Create bind if it doesn't exist
      bind = {
        port,
        listeners: [],
      };
      config.binds.push(bind);
    }

    // Check if listener name already exists in this bind
    const existingIndex = bind.listeners.findIndex((l) => l.name === listener.name);
    if (existingIndex >= 0) {
      bind.listeners[existingIndex] = listener;
    } else {
      bind.listeners.push(listener);
    }

    await updateConfig(config);
  } catch (error) {
    console.error("Error adding listener to bind:", error);
    throw error;
  }
}

/**
 * Removes a listener from its bind
 */
export async function removeListenerFromBind(listenerName: string): Promise<void> {
  try {
    const config = await fetchConfig();

    // Find and remove the listener from all binds
    config.binds.forEach((bind: Bind) => {
      bind.listeners = bind.listeners.filter((l) => l.name !== listenerName);
    });

    // Remove empty binds (optional - you might want to keep empty binds)
    // config.binds = config.binds.filter(bind => bind.listeners.length > 0);

    await updateConfig(config);
  } catch (error) {
    console.error("Error removing listener from bind:", error);
    throw error;
  }
}

/**
 * Moves a listener from one bind to another
 */
export async function moveListenerToBind(
  listenerName: string,
  fromPort: number,
  toPort: number
): Promise<void> {
  try {
    const config = await fetchConfig();

    // Find the listener in the source bind
    const sourceBind = config.binds.find((b) => b.port === fromPort);
    if (!sourceBind) {
      throw new Error(`Source bind for port ${fromPort} not found`);
    }

    const listenerIndex = sourceBind.listeners.findIndex((l) => l.name === listenerName);
    if (listenerIndex === -1) {
      throw new Error(`Listener ${listenerName} not found in port ${fromPort}`);
    }

    const listener = sourceBind.listeners[listenerIndex];

    // Remove from source bind
    sourceBind.listeners.splice(listenerIndex, 1);

    // Add to target bind
    let targetBind = config.binds.find((b) => b.port === toPort);
    if (!targetBind) {
      // Create target bind if it doesn't exist
      targetBind = {
        port: toPort,
        listeners: [],
      };
      config.binds.push(targetBind);
    }

    targetBind.listeners.push(listener);

    await updateConfig(config);
  } catch (error) {
    console.error("Error moving listener between binds:", error);
    throw error;
  }
}

/**
 * Gets bind information for a specific port
 */
export async function getBind(port: number): Promise<Bind | null> {
  try {
    const config = await fetchConfig();
    return config.binds.find((b) => b.port === port) || null;
  } catch (error) {
    console.error("Error getting bind:", error);
    return null;
  }
}

function mapToHeaderModifier(data: any): HeaderModifier | undefined {
  if (!data || typeof data !== "object") return undefined;

  const modifier: HeaderModifier = {};

  if (data.add && typeof data.add === "object") {
    modifier.add = Object.entries(data.add) as [string, string][];
  }

  if (data.set && typeof data.set === "object") {
    modifier.set = Object.entries(data.set) as [string, string][];
  }

  if (Array.isArray(data.remove)) {
    modifier.remove = data.remove as string[];
  }

  return Object.keys(modifier).length > 0 ? modifier : undefined;
}

function mapToAuthorityRewrite(data: any): AuthorityRewrite | undefined {
  if (!data || typeof data !== "object") return undefined;

  const rewrite: AuthorityRewrite = {} as AuthorityRewrite;
  if (typeof data.full === "string") rewrite.full = data.full;
  if (typeof data.host === "string") rewrite.host = data.host;
  if (typeof data.port === "number") rewrite.port = data.port;
  return rewrite;
}

function mapToPathRewrite(data: any): PathRewrite | undefined {
  if (!data || typeof data !== "object") return undefined;
  const rewrite: PathRewrite = {} as PathRewrite;
  if (typeof data.full === "string") rewrite.full = data.full;
  if (typeof data.prefix === "string") rewrite.prefix = data.prefix;
  return rewrite;
}

function mapToRequestRedirect(data: any): RequestRedirect | undefined {
  if (!data || typeof data !== "object") return undefined;

  const redirect: RequestRedirect = {} as RequestRedirect;

  if (typeof data.scheme === "string") redirect.scheme = data.scheme;
  if (data.authority) redirect.authority = mapToAuthorityRewrite(data.authority) ?? null;
  if (data.path) redirect.path = mapToPathRewrite(data.path) ?? null;
  if (typeof data.status === "number") redirect.status = data.status;

  return redirect;
}

function mapToUrlRewrite(data: any): UrlRewrite | undefined {
  if (!data || typeof data !== "object") return undefined;

  const rewrite: UrlRewrite = {} as UrlRewrite;
  if (data.authority) rewrite.authority = mapToAuthorityRewrite(data.authority) ?? null;
  if (data.path) rewrite.path = mapToPathRewrite(data.path) ?? null;
  return rewrite;
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

  const backendRef = mapToBackendRef(data.backend);
  if (!backendRef) return undefined;

  const mirror: RequestMirror = {
    backend: backendRef,
    percentage: typeof data.percentage === "number" ? data.percentage : 100,
  };
  return mirror;
}

function mapToDirectResponse(data: any): DirectResponse | undefined {
  if (!data || typeof data !== "object") return undefined;

  const response: DirectResponse = {
    body: data.body,
    status: typeof data.status === "number" ? data.status : 200,
  };
  return response;
}

function mapToCorsPolicy(data: any): CorsPolicy | undefined {
  if (!data || typeof data !== "object") return undefined;

  const cors: CorsPolicy = {} as CorsPolicy;
  if (typeof data.allowCredentials === "boolean") cors.allowCredentials = data.allowCredentials;
  if (Array.isArray(data.allowHeaders)) cors.allowHeaders = data.allowHeaders as string[];
  if (Array.isArray(data.allowMethods)) cors.allowMethods = data.allowMethods as string[];
  if (Array.isArray(data.allowOrigins)) cors.allowOrigins = data.allowOrigins as string[];
  if (Array.isArray(data.exposeHeaders)) cors.exposeHeaders = data.exposeHeaders as string[];
  if (typeof data.maxAge === "string" || data.maxAge === null) cors.maxAge = data.maxAge;

  return cors;
}

function mapToMcpAuthorization(data: any): McpAuthorization | undefined {
  if (!data || typeof data !== "object" || !Array.isArray(data.rules)) return undefined;
  return { rules: data.rules } as McpAuthorization;
}

function mapToMcpAuthentication(data: any): McpAuthentication | undefined {
  if (!data || typeof data !== "object") return undefined;

  const auth: McpAuthentication = {
    issuer: String(data.issuer ?? ""),
    scopes: Array.isArray(data.scopes) ? data.scopes : [],
    provider: data.provider as any,
  };

  return auth;
}

function mapToBackendTLS(data: any): BackendTLS | undefined {
  if (!data || typeof data !== "object") return undefined;

  const tls: BackendTLS = {} as BackendTLS;
  if (typeof data.cert === "string" || data.cert === null) tls.cert = data.cert;
  if (typeof data.key === "string" || data.key === null) tls.key = data.key;
  if (typeof data.root === "string" || data.root === null) tls.root = data.root;
  if (typeof data.insecure === "boolean") tls.insecure = data.insecure;
  if (typeof data.insecureHost === "boolean") tls.insecureHost = data.insecureHost;
  return tls;
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

  const jwt: JwtAuth = {
    issuer: String(data.issuer ?? ""),
    audiences: Array.isArray(data.audiences) ? data.audiences : [],
    jwks: data.jwks,
  };
  return jwt;
}

function mapToExtAuthz(data: any): any {
  if (!data || typeof data !== "object") return undefined;
  // Minimal mapping – return as-is for now.
  return data;
}

function mapToTimeoutPolicy(data: any): TimeoutPolicy | undefined {
  if (!data || typeof data !== "object") return undefined;
  const timeout: TimeoutPolicy = {
    requestTimeout: data.requestTimeout ?? null,
    backendRequestTimeout: data.backendRequestTimeout ?? null,
  };
  return timeout;
}

function mapToRetryPolicy(data: any): RetryPolicy | undefined {
  if (!data || typeof data !== "object") return undefined;

  const retry: RetryPolicy = {
    attempts: typeof data.attempts === "number" ? data.attempts : undefined,
    backoff: data.backoff ?? null,
    codes: Array.isArray(data.codes) ? data.codes : [],
  };

  return retry;
}
