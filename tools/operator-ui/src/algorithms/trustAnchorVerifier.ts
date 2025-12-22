/**
 * Algorithm 7: TrustAnchorVerifier
 * 
 * Verifies trust anchor configuration from environment.
 * 
 * @complexity O(1)
 * @invariant I1: Never display raw key material, only fingerprints
 * 
 * @precondition Environment variables are accessible
 * @postcondition Returns verification result with fingerprints only
 */

import type { TrustAnchors } from '../api/types';

// =============================================================================
// Types
// =============================================================================

export interface TrustAnchorVerification {
    configured: boolean;
    registryStatePath: string | null;
    registryKeyFingerprint: string | null;
    manifestKeyFingerprint: string | null;
    warnings: string[];
}

// =============================================================================
// Pure Functions
// =============================================================================

/**
 * Compute fingerprint from hex key (first 8 bytes of value, displayed as hex).
 * 
 * @invariant Never returns full key material
 */
function computeFingerprint(hexKey: string | undefined): string | null {
    if (!hexKey) {
        return null;
    }
    // Take first 16 hex chars (8 bytes), add ellipsis for display
    const truncated = hexKey.slice(0, 16).toUpperCase();
    return truncated.length >= 16 ? `${truncated}…` : null;
}

// =============================================================================
// Main Algorithm
// =============================================================================

/**
 * Verify trust anchor configuration.
 * 
 * Algorithm 7: TrustAnchorVerifier
 * 
 * @complexity O(1)
 * @invariant UI MUST display only fingerprints + paths; never display raw key material
 */
export function verifyTrustAnchors(anchors: TrustAnchors): TrustAnchorVerification {
    const warnings: string[] = [];

    // Check registry state path
    const registryStatePath = anchors.registryStatePath ?? null;
    if (!registryStatePath) {
        warnings.push('MPRD_OPERATOR_REGISTRY_STATE_PATH not configured');
    }

    // Get fingerprints (already fingerprinted in backend, but validate)
    const registryKeyFingerprint = anchors.registryKeyFingerprint ?? null;
    if (!registryKeyFingerprint) {
        warnings.push('MPRD_OPERATOR_REGISTRY_KEY_HEX not configured');
    }

    // Manifest key defaults to registry key if not specified
    const manifestKeyFingerprint = anchors.manifestKeyFingerprint ?? registryKeyFingerprint;
    if (!anchors.manifestKeyFingerprint && !registryKeyFingerprint) {
        warnings.push('MPRD_OPERATOR_MANIFEST_KEY_HEX not configured');
    }

    // All three must be present for configured = true
    const configured = Boolean(
        registryStatePath &&
        registryKeyFingerprint &&
        manifestKeyFingerprint
    );

    return {
        configured,
        registryStatePath,
        registryKeyFingerprint,
        manifestKeyFingerprint,
        warnings,
    };
}

/**
 * Create trust anchors verification from raw environment values.
 * Use this for client-side verification when environment is accessible.
 */
export function createTrustAnchorsFromEnv(env: {
    registryStatePath?: string;
    registryKeyHex?: string;
    manifestKeyHex?: string;
}): TrustAnchors {
    return {
        registryStatePath: env.registryStatePath,
        registryKeyFingerprint: computeFingerprint(env.registryKeyHex) ?? undefined,
        manifestKeyFingerprint: computeFingerprint(env.manifestKeyHex) ??
            computeFingerprint(env.registryKeyHex) ?? undefined,
    };
}

/**
 * Check if trust anchors are fully configured.
 */
export function areTrustAnchorsConfigured(anchors: TrustAnchors): boolean {
    return Boolean(
        anchors.registryStatePath &&
        anchors.registryKeyFingerprint &&
        anchors.manifestKeyFingerprint
    );
}
