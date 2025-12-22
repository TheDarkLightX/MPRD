/**
 * Algorithm 2: ModeAdaptiveUIRenderer
 * 
 * Determines visible sections and disclosure policy based on deployment mode.
 * 
 * @complexity O(1)
 * @invariant I1: Missing trust anchors in trustless/private → pipeline disabled
 * @invariant I2: Local mode never shows ZK features
 * 
 * @precondition mode is a valid DeploymentMode
 * @postcondition Returns UIRenderConfig with fail-closed safety
 */

import type {
    DeploymentMode,
    TrustAnchors,
    UIRenderConfig,
    DisclosurePolicy,
} from '../api/types';

// =============================================================================
// Warning Constants
// =============================================================================

export const INSECURE_DEMO_WARNING = 'InsecureDemoWarning';
export const TRUST_ANCHORS_CRITICAL = 'TrustAnchorsCritical';

// =============================================================================
// Section Definitions
// =============================================================================

const BASE_SECTIONS = ['dashboard', 'decisions', 'alerts', 'settings'] as const;
const TRUSTLESS_SECTIONS = [...BASE_SECTIONS, 'trust_anchors', 'proof_explorer'] as const;
const PRIVATE_SECTIONS = [...TRUSTLESS_SECTIONS, 'privacy_settings'] as const;

const ZK_ACTIONS = ['verify_proof', 'export_receipt'] as const;
const PIPELINE_ACTIONS = ['run_pipeline'] as const;

// =============================================================================
// Pure Functions
// =============================================================================

/**
 * Check if trust anchors are configured.
 */
function areAnchorsConfigured(anchors: TrustAnchors): boolean {
    return Boolean(
        anchors.registryStatePath &&
        anchors.registryKeyFingerprint &&
        anchors.manifestKeyFingerprint
    );
}

/**
 * Get disclosure policy for a deployment mode.
 */
function getDisclosurePolicy(mode: DeploymentMode): DisclosurePolicy {
    switch (mode) {
        case 'local':
            return 'HashFirstStrict';
        case 'trustless':
            return 'HashFirstWithTimedReveal';
        case 'private':
            return 'HashFirstWithTimedRevealAndRedaction';
    }
}

// =============================================================================
// Main Algorithm
// =============================================================================

export interface ModeAdaptiveInput {
    mode: DeploymentMode;
    trustAnchors: TrustAnchors;
    storeSensitive?: boolean;
}

/**
 * Render UI configuration based on deployment mode.
 * 
 * Algorithm 2: ModeAdaptiveUIRenderer
 * 
 * @complexity O(1)
 * @invariant I1: Missing anchors in trustless/private → run_pipeline disabled
 * @invariant I2: Local mode never shows ZK sections
 */
export function computeUIRenderConfig(input: ModeAdaptiveInput): UIRenderConfig {
    const { mode, trustAnchors } = input;
    const anchorsConfigured = areAnchorsConfigured(trustAnchors);

    switch (mode) {
        case 'local':
            return {
                visibleSections: [...BASE_SECTIONS],
                disabledActions: [...ZK_ACTIONS],
                warnings: [INSECURE_DEMO_WARNING],
                disclosurePolicy: getDisclosurePolicy(mode),
            };

        case 'trustless':
            return {
                visibleSections: [...TRUSTLESS_SECTIONS],
                disabledActions: anchorsConfigured ? [] : [...PIPELINE_ACTIONS],
                warnings: anchorsConfigured ? [] : [TRUST_ANCHORS_CRITICAL],
                disclosurePolicy: getDisclosurePolicy(mode),
            };

        case 'private':
            return {
                visibleSections: [...PRIVATE_SECTIONS],
                disabledActions: anchorsConfigured ? [] : [...PIPELINE_ACTIONS],
                warnings: anchorsConfigured ? [] : [TRUST_ANCHORS_CRITICAL],
                disclosurePolicy: getDisclosurePolicy(mode),
            };
    }
}

/**
 * Check if an action is disabled in current configuration.
 */
export function isActionDisabled(config: UIRenderConfig, action: string): boolean {
    return config.disabledActions.includes(action);
}

/**
 * Check if a section is visible in current configuration.
 */
export function isSectionVisible(config: UIRenderConfig, section: string): boolean {
    return config.visibleSections.includes(section);
}

/**
 * Get the most severe warning from configuration.
 */
export function getMostSevereWarning(config: UIRenderConfig): string | null {
    if (config.warnings.includes(TRUST_ANCHORS_CRITICAL)) {
        return TRUST_ANCHORS_CRITICAL;
    }
    if (config.warnings.includes(INSECURE_DEMO_WARNING)) {
        return INSECURE_DEMO_WARNING;
    }
    return config.warnings[0] ?? null;
}
