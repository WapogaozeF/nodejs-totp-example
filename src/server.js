import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import { hash, verify } from "argon2";
import qrcode from "qrcode";
import { PrismaClient } from "@prisma/client";
import { authenticator } from "otplib";
import { encryptSecret, decodeSecret } from "./utils/cryptoHelpers.js";
import qrcodeTerminal from "qrcode-terminal";

const PORT = process.env.PORT || 3000;

const prisma = new PrismaClient();
const app = express();
app.use(bodyParser.json());

app.post("/registry", async (req, res) => {
	const { email, password } = req.body;
	const passwordHash = await hash(password);
	const user = await prisma.user.create({
		data: { email, passwordHash },
	});
	res.json({ ok: true, userId: user.id });
});

app.post("/2fa/setup", async (req, res) => {
	const userId = req.body.userId;
	const user = await prisma.user.findUnique({ where: { id: userId } });
	if (!user) return res.status(404).json({ error: "user not found" });

	const secret = authenticator.generateSecret();
	const serviceName = "MyApp";
	const otpauth = authenticator.keyuri(user.email, serviceName, secret);

	const enc = encryptSecret(secret);
	await prisma.user.update({
		where: { id: userId },
		data: {
			totpSecretEncrypted: enc.chipherText,
			totpSecretIv: enc.iv,
			totpSecretTag: enc.tag,
		},
	});

	const qrDataUrl = await qrcode.toDataURL(otpauth);
	console.log(await qrcodeTerminal.generate(otpauth, { small: true }));
	res.json({ otpauth, qrDataUrl });
});

app.post("/2fa/confirm", async (req, res) => {
	const { userId, token } = req.body;
	const user = await prisma.user.findUnique({ where: { id: userId } });

	if (!user || !user.totpSecretEncrypted)
		return res.status(400).json({ error: "setup not started" });

	const secret = decodeSecret({
		chipherText: user.totpSecretEncrypted,
		iv: user.totpSecretIv,
		tag: user.totpSecretTag,
	});

	const isValid = authenticator.verify({ token, secret });
	if (!isValid) return res.status(400).json({ error: "invalid token" });

	const recoveryPlain = Array.from({ length: 10 }).map(() =>
		Math.random().toString(36).slice(2, 10),
	);
	const recoveryHashes = await Promise.all(recoveryPlain.map((c) => hash(c)));

	await prisma.user.update({
		where: { id: userId },
		data: {
			totpEnabled: true,
			recoveryCodesJson: JSON.stringify(recoveryHashes),
		},
	});

	res.json({ ok: true, recoveryCodes: recoveryPlain });
});

app.post("/login", async (req, res) => {
	const { email, password, token, recoveryCode } = req.body;
	const user = await prisma.user.findUnique({ where: { email } });
	if (!user) return res.status(400).json({ error: "invalid credential" });

	const pwOk = await verify(user.passwordHash, password);
	if (!pwOk) return res.status(400).json({ error: "invalid credential" });

	if (!user.totpEnabled) {
		return res.json({ ok: true, message: "logged in (no 2FA)" });
	}

	if (token) {
		const secret = decodeSecret({
			chipherText: user.totpSecretEncrypted,
			iv: user.totpSecretIv,
			tag: user.totpSecretTag,
		});
		const isValid = authenticator.verify({ token, secret });
		if (isValid) {
			return res.json({ ok: true, message: "logged in (2FA ok)" });
		} else {
			return res.status(401).json({ error: "invalid 2FA token" });
		}
	}

	if (recoveryCode) {
		const recoveryHashes = JSON.parse(user.recoveryCodesJson || "[]");
		for (let i = 0; i < recoveryHashes.length; i++) {
			const h = recoveryHashes[i];
			try {
				if (await verify(h, recoveryCode)) {
					recoveryHashes.splice(i, 1);
					await prisma.user.update({
						where: { id: user.id },
						data: { recoveryCodesJson: JSON.stringify(recoveryHashes) },
					});
					return res.json({
						ok: true,
						message: "logged in (user recovery code)",
					});
				}
			} catch (e) {}
		}
	}
	res.status(206).json({ need2fa: true });
});

app.listen(PORT, () => console.log(`Server listen on port ${PORT}`));
