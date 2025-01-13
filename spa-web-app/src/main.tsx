import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { UserManagerSettings } from "oidc-client-ts";
import { AuthProvider } from "react-oidc-context";

const CLIENT_ID = "public-client";
const AUTH_SERVER_URL = "http://authserver:9000";
const HOST_URL = window.location.origin;

const oidcConfig: UserManagerSettings = {
  authority: AUTH_SERVER_URL,
  client_id: CLIENT_ID,
  redirect_uri: HOST_URL + "/callback",
  response_type: "code",
  scope: "openid profile email",
};

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <AuthProvider {...oidcConfig}>
      <App />
    </AuthProvider>
  </StrictMode>,
);
