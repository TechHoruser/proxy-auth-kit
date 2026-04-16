// Authelia configuration generator — usado por setup.ts y control.ts

import type { Config } from "./nginx-config.js";

export const generateAutheliaConf = (config: Config, domain: string): string => {
  const rules: string[] = [];

  for (const svc of config.services) {
    if (!svc.protected) continue;

    const svcDomain = `${svc.subdomain}.${domain}`;

    if (svc.groups && svc.groups.length > 0) {
      const subjects = svc.groups.map((g) => `        - 'group:${g}'`).join("\n");
      rules.push(
        `    - domain: '${svcDomain}'\n      subject:\n${subjects}\n      policy: one_factor`,
      );
    } else {
      rules.push(`    - domain: '${svcDomain}'\n      policy: one_factor`);
    }
  }

  // Sin servicios definidos → ninguna regla explícita; default_policy: deny lo cubre todo
  const rulesBlock = rules.join("\n");

  return `###############################################################
#                   Authelia Configuration                    #
# Generado automáticamente por proxy-auth-kit.               #
# No editar manualmente — usar: npm run control              #
###############################################################

theme: dark

server:
  address: "tcp://0.0.0.0:9091/"

log:
  level: info

authentication_backend:
  file:
    path: /config/users_database.yml
    watch: true

access_control:
  default_policy: deny${rulesBlock ? `\n  rules:\n${rulesBlock}` : ""}

session:
  cookies:
    - name: authelia_session
      domain: '${domain}'
      authelia_url: 'https://auth.${domain}/'
      expiration: 3600
      inactivity: 300

regulation:
  max_retries: 3
  find_time: 120
  ban_time: 300

storage:
  local:
    path: /data/db.sqlite3

notifier:
  filesystem:
    filename: /data/notifications.txt
`;
};
