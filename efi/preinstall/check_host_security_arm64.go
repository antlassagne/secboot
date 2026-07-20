// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package preinstall

import (
	"errors"
	"fmt"

	"github.com/canonical/tcglog-parser"

	internal_efi "github.com/snapcore/secboot/internal/efi"
)

// checkHostSecurity runs the architecture-neutral host security checks on arm64.
//
// Note that arm64 has no equivalent of the x86 hardware root-of-trust checks
// (Intel BootGuard / CPU debugging locked, AMD PSP), so platform firmware
// integrity is always reported as unverified. Only the architecture-neutral
// checks (TCG log inspection for degraded firmware settings and kernel IOMMU
// support) are performed here.
//
// Errors that can't be resolved or which should prevent further checks from
// running are returned immediately and without any wrapping. Errors that can be
// resolved and which shouldn't prevent further checks from running are returned
// wrapped in [joinErrors].
func checkHostSecurity(env internal_efi.HostEnvironment, log *tcglog.Log) (platformFirmwareIntegrityConfig, error) {
	var errs []error

	if err := checkSecureBootPolicyPCRForDegradedFirmwareSettings(log); err != nil {
		var ce CompoundError
		if !errors.As(err, &ce) {
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error whilst checking the TCG log for degraded firmware settings: %w", err)
		}
		errs = append(errs, ce.Unwrap()...)
	}
	if err := checkForKernelIOMMU(env); err != nil {
		switch {
		case errors.Is(err, ErrNoKernelIOMMU):
			errs = append(errs, err)
		default:
			return platformFirmwareIntegrityNone, fmt.Errorf("encountered an error whilst checking sysfs to determine that kernel IOMMU support is enabled: %w", err)
		}
	}

	if len(errs) > 0 {
		return platformFirmwareIntegrityNone, joinErrors(errs...)
	}

	// arm64 has no supported hardware root-of-trust check, so platform
	// firmware integrity cannot be verified here.
	return platformFirmwareIntegrityNone, nil
}

func checkDiscreteTPMPartialResetAttackMitigationStatus(env internal_efi.HostEnvironment, logResults *pcrBankResults) (discreteTPMPartialResetAttackMitigationStatus, error) {
	// The partial discrete TPM reset attack mitigation is only enabled on
	// Intel systems, so it is not required on arm64.
	return dtpmPartialResetAttackMitigationNotRequired, nil
}
