import type { RouteDef } from "../route-config";
import { IdentityProviderRoute } from "./routes/IdentityProvider";
import { IdentityProviderKeycloakOidcRoute } from "./routes/IdentityProviderKeycloakOidc";
import { IdentityProviderOidcRoute } from "./routes/IdentityProviderOidc";
import { IdentityProvidersRoute } from "./routes/IdentityProviders";
import { IdentityProviderTabRoute } from "./routes/IdentityProviderTab";

const routes: RouteDef[] = [
  IdentityProvidersRoute,
  IdentityProviderOidcRoute,
  IdentityProviderKeycloakOidcRoute,
  IdentityProviderRoute,
  IdentityProviderTabRoute,
];

export default routes;
