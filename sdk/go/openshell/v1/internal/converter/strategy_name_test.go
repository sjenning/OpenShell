// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
)

func TestRefreshStrategyNamesPreserveIndependentEnumAndNameSelectors(t *testing.T) {
	config := &types.RefreshConfig{StrategyName: "oauth2_client_credentials"}
	wire := RefreshConfigToProto(config)
	assert.Equal(t, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_UNSPECIFIED, wire.Strategy)
	assert.Equal(t, config.StrategyName, wire.StrategyName)
	profile := &types.ProfileCredentialRefresh{StrategyName: "oauth2_refresh_token"}
	assert.Equal(t, profile, profileCredentialRefreshFromProto(profileCredentialRefreshToProto(profile)))
	status := RefreshStatusFromProto(&pb.ProviderCredentialRefreshStatus{StrategyName: "oauth2_refresh_token"})
	assert.Equal(t, "oauth2_refresh_token", status.StrategyName)
	// Pass conflicting/unknown selections to the authoritative server; a
	// converter must not silently turn a caller's name into another strategy.
	config.Strategy = types.RefreshStrategyStatic
	config.StrategyName = "custom:unregistered"
	wire = RefreshConfigToProto(config)
	assert.Equal(t, pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_STATIC, wire.Strategy)
	assert.Equal(t, "custom:unregistered", wire.StrategyName)
}
