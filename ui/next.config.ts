import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  basePath: "/ui",
  trailingSlash: true,
  env: {
    XDS_ADDRESS: process.env.XDS_ADDRESS,
  },
};

export default nextConfig;
