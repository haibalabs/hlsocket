/* hlab_socket
 * https://github.com/haibalabs/hlsocket
 * See LICENSE.txt for copyright and licensing details.
 */

struct HLSocketSSL {
	mbedtls_net_context ctx;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt cert;
	mbedtls_dhm_context dhm;
	mbedtls_pk_context pkey;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
#ifdef MBEDTLS_SSL_CACHE_C
	mbedtls_ssl_cache_context cache;
#endif // MBEDTLS_SSL_CACHE_C
	bool listen;
};

static void* readFileToMemory(const char* path, size_t* outSize) {
	FILE* file = fopen(path, "rb");
	if (!file) {
		if (outSize) {
			*outSize = 0;
		}
		return nullptr;
	}

	int64_t curr = ftell(file);
	fseek(file, 0, SEEK_END);
	int64_t size = ftell(file);
	fseek(file, curr, SEEK_SET);

	if (outSize) {
		*outSize = (size_t)size;
	}

	void* buf = HL_MALLOC((size_t)size + 2);

	if (buf) {
		size_t read = fread(buf, 1, (size_t)size, file);
		*(((uint8_t*)buf) + size + 0) = 0;
		*(((uint8_t*)buf) + size + 1) = 0; // null-terminate the buffer, in case it's a text file
	}

	fseek(file, 0, SEEK_SET);

	return buf;
}

static void hlsocketSSLDbgLog(void*, int level, const char* file, int line, const char* str) {
#if HLSOCKET_ENABLE_SSL_DBG_LOGS
	size_t len = str ? ::strlen(str) : 0;

	if (len) {
		--len;

		if (level <= 1) {
			HL_LOG("mbedtls [%s:%d] %*.*s\n", file, line, 0, (int)len, str);
		}
		else {
			HL_LOG("mbedtls [%s:%d] %*.*s\n", file, line, 0, (int)len, str);
		}
	}
#endif // HLSOCKET_ENABLE_SSL_DBG_LOGS
}

static void hlsocketSSLCleanup(HLSocketSSL*& sslCtx) {
	mbedtls_net_free(&sslCtx->ctx);
	mbedtls_ssl_free(&sslCtx->ssl);
	mbedtls_ssl_config_free(&sslCtx->conf);
	mbedtls_x509_crt_free(&sslCtx->cert);
	mbedtls_pk_free(&sslCtx->pkey);
	mbedtls_entropy_free(&sslCtx->entropy);
	mbedtls_dhm_free(&sslCtx->dhm);
	mbedtls_ctr_drbg_free(&sslCtx->ctr_drbg);
#ifdef MBEDTLS_SSL_CACHE_C
	mbedtls_ssl_cache_free(&sslCtx->cache);
#endif // MBEDTLS_SSL_CACHE_C
	delete sslCtx;
	sslCtx = nullptr;
}

static bool hlsocketSSLInit(HLSocket s, bool listen) {
	if (s->sslCtx) {
		return true;
	}

	if (!gSSLCertFilename || !gSSLPrivKeyFilename) {
		return false;
	}

#ifdef MBEDTLS_DEBUG_C
#ifdef NDEBUG
	mbedtls_debug_set_threshold(0);
#else
	mbedtls_debug_set_threshold(1);
#endif // NDEBUG
#endif // MBEDTLS_DEBUG_C

	HLSocketSSL* sslCtx = new HLSocketSSL;
	memset(sslCtx, 0, sizeof(HLSocketSSL));
	sslCtx->listen = listen;

	mbedtls_net_init(&sslCtx->ctx);
	mbedtls_ssl_init(&sslCtx->ssl);
	mbedtls_ssl_config_init(&sslCtx->conf);
#ifdef MBEDTLS_SSL_CACHE_C
	mbedtls_ssl_cache_init(&sslCtx->cache);
#endif // MBEDTLS_SSL_CACHE_C
	mbedtls_x509_crt_init(&sslCtx->cert);
	mbedtls_pk_init(&sslCtx->pkey);
	mbedtls_entropy_init(&sslCtx->entropy);
	mbedtls_ctr_drbg_init(&sslCtx->ctr_drbg);

	// Read cert
	size_t crtDataSz = 0;
	void* crtData = readFileToMemory(gSSLCertFilename, &crtDataSz);
	if (!crtData) {
		HL_LOG("Failed to load SSL cert \"%s\"\n", gSSLCertFilename);
		hlsocketSSLCleanup(sslCtx);
		return false;
	}

	crtDataSz += 1; // include the null terminator

	int rcCert = mbedtls_x509_crt_parse(&sslCtx->cert, (const unsigned char*)crtData, crtDataSz);
	HL_FREE(crtData);

	if (0 != rcCert) {
		HL_LOG("Failed to configure SSL cert: %d (-0x%x)\n", rcCert, abs(rcCert));
		hlsocketSSLCleanup(sslCtx);
		return false;
	}

	// Read key
	size_t crtPrivSz = 0;
	void* crtPriv = readFileToMemory(gSSLPrivKeyFilename, &crtPrivSz);
	if (!crtPriv) {
		HL_LOG("Failed to load SSL key \"%s\"\n", gSSLCertFilename);
		hlsocketSSLCleanup(sslCtx);
		return false;
	}

	crtPrivSz += 1; // include the null terminator

	int rcPriv = mbedtls_pk_parse_key(&sslCtx->pkey, (const unsigned char*)crtPriv, crtPrivSz, nullptr, 0, nullptr, nullptr);
	HL_FREE(crtPriv);
	if (0 != rcPriv) {
		HL_LOG("Failed to configure SSL private key: %d (-0x%x)\n", rcPriv, abs(rcPriv));
		hlsocketSSLCleanup(sslCtx);
		return false;
	}

	s->sslCtx = sslCtx;
	s->flags |= HLSocketData::kSSLParent | HLSocketData::kSSL;

	return true;
}

static bool hlsocketSSLPreAccept(HLSocket bindSock) {
	if (bindSock->flags & HLSocketData::kSSLParent) {
		HLSocketSSL* parentCtx = bindSock->sslCtx;
		HL_ASSERT(parentCtx);

		mbedtls_ssl_session_reset(&parentCtx->ssl);
	}

	return true;
}

static bool hlsocketSSLAccept(HLSocket bindSock, HLSocket clientSock) {
	if (bindSock->flags & HLSocketData::kSSLParent) {
		HLSocketSSL* parentCtx = bindSock->sslCtx;
		HL_ASSERT(parentCtx);

		HLSocketSSL* clientCtx = new HLSocketSSL;
		memset(clientCtx, 0, sizeof(HLSocketSSL));

		mbedtls_net_init(&clientCtx->ctx);
		clientCtx->ctx.fd = clientSock->s;

		mbedtls_ssl_init(&clientCtx->ssl);
		int rcSetup = mbedtls_ssl_setup(&clientCtx->ssl, &parentCtx->conf);
		if (0 != rcSetup) {
			HL_LOG("Failed to setup SSL: mbedtls_ssl_setup returned %d (-0x%x)\n", rcSetup, abs(rcSetup));
			hlsocketSSLCleanup(clientCtx);
			return false;
		}
		mbedtls_ssl_set_bio(&clientCtx->ssl, &clientCtx->ctx, mbedtls_net_send, mbedtls_net_recv, nullptr);

		clientSock->sslCtx = clientCtx;
		clientSock->flags |= HLSocketData::kSSL;

		int rcShake;
		while ((rcShake = mbedtls_ssl_handshake(&clientCtx->ssl))) {
			if (rcShake != MBEDTLS_ERR_SSL_WANT_READ && rcShake != MBEDTLS_ERR_SSL_WANT_WRITE) {
				HL_LOG("Failed SSL handshake: mbedtls_ssl_handshake returned %d (-0x%x)\n", rcShake, abs(rcShake));
				return false;
			}
		}
	}

	return true;
}

static bool hlsocketSSLConnect(HLSocket s, const char* host) {
	if (s->flags & HLSocketData::kSSLParent) {
		HLSocketSSL* sslCtx = s->sslCtx;
		HL_ASSERT(sslCtx);

#if HLSOCKET_ENABLE_SSL
		sslCtx->ctx.fd = s->s;
#endif // HLSOCKET_ENABLE_SSL

		static const char* pers = "hp_ssl_client";

		int rcSeed = mbedtls_ctr_drbg_seed(&sslCtx->ctr_drbg, mbedtls_entropy_func, &sslCtx->entropy, (const unsigned char*)pers, ::strlen(pers));
		if (0 != rcSeed) {
			HL_LOG("Failed to set SSL seed: mbedtls_ctr_drbg_seed returned %d (-0x%x)\n", rcSeed, abs(rcSeed));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		int rcCfg = mbedtls_ssl_config_defaults(&sslCtx->conf,
			sslCtx->listen ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		if (0 != rcCfg) {
			HL_LOG("Failed to set SSL defaults: mbedtls_ssl_config_defaults returned %d (-0x%x)\n", rcCfg, abs(rcCfg));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		mbedtls_ssl_conf_rng(&sslCtx->conf, mbedtls_ctr_drbg_random, &sslCtx->ctr_drbg);
		mbedtls_ssl_conf_dbg(&sslCtx->conf, hlsocketSSLDbgLog, stdout);

#ifdef MBEDTLS_SSL_CACHE_C
		mbedtls_ssl_conf_session_cache(&sslCtx->conf, &sslCtx->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif // MBEDTLS_SSL_CACHE_C

		mbedtls_ssl_conf_ca_chain(&sslCtx->conf, sslCtx->cert.next, nullptr);

		int rcConf = mbedtls_ssl_conf_own_cert(&sslCtx->conf, &sslCtx->cert, &sslCtx->pkey);
		if (0 != rcConf) {
			HL_LOG("Failed to configure SSL cert: mbedtls_ssl_conf_own_cert returned %d (-0x%x)\n", rcConf, abs(rcConf));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		int rcSetup = mbedtls_ssl_setup(&sslCtx->ssl, &sslCtx->conf);
		if (0 != rcSetup) {
			HL_LOG("Failed to setup SSL: mbedtls_ssl_setup returned %d (-0x%x)\n", rcSetup, abs(rcSetup));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		int rcHost = mbedtls_ssl_set_hostname(&sslCtx->ssl, host);
		if (0 != rcHost) {
			HL_LOG("Failed to set hostname SSL: mbedtls_ssl_set_hostname returned %d (-0x%x)\n", rcHost, abs(rcHost));
			return false;
		}

		mbedtls_ssl_set_bio(&sslCtx->ssl, &sslCtx->ctx, mbedtls_net_send, mbedtls_net_recv, nullptr);

		mbedtls_ssl_set_hs_authmode(&sslCtx->ssl, MBEDTLS_SSL_VERIFY_NONE);

		int rcShake;
		while ((rcShake = mbedtls_ssl_handshake(&sslCtx->ssl))) {
			if (rcShake != MBEDTLS_ERR_SSL_WANT_READ && rcShake != MBEDTLS_ERR_SSL_WANT_WRITE) {
				HL_LOG("Failed SSL handshake: mbedtls_ssl_handshake returned %d (-0x%x)\n", rcShake, abs(rcShake));
				//exit(-1);
				return false;
			}
		}

		int rcVerify = mbedtls_ssl_get_verify_result(&sslCtx->ssl);
		if (0 != rcVerify) {
			HL_LOG("Failed SSL cert verification: mbedtls_ssl_get_verify_result returned %d (-0x%x)\n", rcVerify, abs(rcVerify));
			return false;
		}
	}

	return true;
}

static bool hlsocketSSLBind(HLSocket s) {
	HLSocketSSL* sslCtx = s->sslCtx;

	if (s->flags & HLSocketData::kSSL) {
		sslCtx->ctx.fd = s->s;
	}

	if (s->flags & HLSocketData::kSSLParent) {
		static const char* pers = "hp_ssl_server";

		int rcSeed = mbedtls_ctr_drbg_seed(&sslCtx->ctr_drbg, mbedtls_entropy_func, &sslCtx->entropy, (const unsigned char*)pers, ::strlen(pers));
		if (0 != rcSeed) {
			HL_LOG("Failed to set SSL seed: mbedtls_ctr_drbg_seed returned %d (-0x%x)\n", rcSeed, abs(rcSeed));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		int rcCfg = mbedtls_ssl_config_defaults(&sslCtx->conf,
			sslCtx->listen ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		if (0 != rcCfg) {
			HL_LOG("Failed to set SSL defaults: mbedtls_ssl_config_defaults returned %d (-0x%x)\n", rcCfg, abs(rcCfg));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		mbedtls_ssl_conf_rng(&sslCtx->conf, mbedtls_ctr_drbg_random, &sslCtx->ctr_drbg);
		mbedtls_ssl_conf_dbg(&sslCtx->conf, hlsocketSSLDbgLog, stdout);

#ifdef MBEDTLS_SSL_CACHE_C
		mbedtls_ssl_conf_session_cache(&sslCtx->conf, &sslCtx->cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif // MBEDTLS_SSL_CACHE_C

		mbedtls_ssl_conf_ca_chain(&sslCtx->conf, sslCtx->cert.next, nullptr);

		int rcConf = mbedtls_ssl_conf_own_cert(&sslCtx->conf, &sslCtx->cert, &sslCtx->pkey);
		if (0 != rcConf) {
			HL_LOG("Failed to configure SSL cert: mbedtls_ssl_conf_own_cert returned %d (-0x%x)\n", rcConf, abs(rcConf));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}

		int rcSetup = mbedtls_ssl_setup(&sslCtx->ssl, &sslCtx->conf);
		if (0 != rcSetup) {
			HL_LOG("Failed to setup SSL: mbedtls_ssl_setup returned %d (-0x%x)\n", rcSetup, abs(rcSetup));
			hlsocketSSLCleanup(sslCtx);
			return false;
		}
	}

	return true;
}

static void hlsocketSSLFini(HLSocket s) {
	if ((s->flags & HLSocketData::kSSL) && s->sslCtx) {
		hlsocketSSLCleanup(s->sslCtx);
		s->sslCtx = nullptr;
	}

	s->flags &= ~HLSocketData::kSSLParent;
	s->flags &= ~HLSocketData::kSSL;
}
