import { ScalekitClient, User } from '@scalekit-sdk/node';
import bodyParser from 'body-parser';
import cookieParser from "cookie-parser";
import express from "express";
import path from "path";

const port = process.env.PORT || 8080;
const app = express();
const scalekit = new ScalekitClient(
  process.env.SCALEKIT_ENV_URL!,
  process.env.SCALEKIT_CLIENT_ID!,
  process.env.SCALEKIT_CLIENT_SECRET!,
);
const users = new Map<string, User>();

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json());
app.use(cookieParser());


app.use(express.static(path.join(__dirname, 'web/build')));

app.get("/auth/me", async (req, res) => {
  const uid = req.cookies.uid;
  if (!uid) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  const user = users.get(uid);
  if (!user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  return res.json(user);
})

app.post("/auth/login", async (req, res) => {
  const { connectionId, email, organizationId } = req.body;
  const url = scalekit.getAuthorizationUrl(
    process.env.AUTH_REDIRECT_URI!,
    {
      connectionId,
      organizationId,
      loginHint: email,
    }
  )
  return res.json({
    url
  });
})

app.get("/auth/callback", async (req, res) => {
  const { code, error_description, idp_initiated_login } = req.query;
  if (error_description) {
    return res.status(400).json({ message: error_description });
  }

  if (idp_initiated_login) {
    const {connection_id, organization_id, login_hint, relay_state} = await scalekit.getIdpInitiatedLoginClaims(idp_initiated_login as string);
    const url = scalekit.getAuthorizationUrl(
      process.env.AUTH_REDIRECT_URI!,
      {
        connectionId: connection_id,
        organizationId: organization_id,
        loginHint: login_hint,
      }
    )
    return res.redirect(url);
  }

  const { user } = await scalekit.authenticateWithCode(
    code as string,
    process.env.AUTH_REDIRECT_URI!,
  );
  users.set(user.id, user);
  res.cookie("uid", user.id, { httpOnly: true });

  return res.redirect("/profile");
})

app.post("/auth/logout", async (_, res) => {
  res.clearCookie("uid");
  return res.redirect("/");
})

// To handle the React 404 routing, return the index.html file
app.use((_, res) => {
  return res.sendFile(path.join(__dirname, 'web/build', 'index.html'));
})

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
})
