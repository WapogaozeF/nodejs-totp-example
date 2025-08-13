import crypto from "node:crypto";

const ALGO = "aes-256-gcm";
const KEY_LEN = 32;
const IV_LEN = 12;

const MASTER_KEY = Buffer.from(process.env.TOTP_ENC_KEY || "", "base64");
if (MASTER_KEY.length !== KEY_LEN) {
	throw new Error("TOTP_ENC_KEY must be 32 bytes (base64).");
}

export function encryptSecret(plain) {
	const iv = crypto.randomBytes(IV_LEN);
	const chipher = crypto.createCipheriv(ALGO, MASTER_KEY, iv, {
		authTagLength: 16,
	});
	const chipherText = Buffer.concat([
		chipher.update(plain, "utf-8"),
		chipher.final(),
	]);
	const tag = chipher.getAuthTag();
	return {
		chipherText: chipherText.toString("base64"),
		iv: iv.toString("base64"),
		tag: tag.toString("base64"),
	};
}

export function decodeSecret({ chipherText, iv, tag }) {
	const dechiper = crypto.createDecipheriv(
		ALGO,
		MASTER_KEY,
		Buffer.from(iv, "base64"),
		{ authTagLength: 16 },
	);
	dechiper.setAuthTag(Buffer.from(tag, "base64"));
	const plain = Buffer.concat([
		dechiper.update(Buffer.from(chipherText, "base64")),
		dechiper.final(),
	]);
	return plain.toString("utf8");
}
