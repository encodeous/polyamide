/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

// DisableSomeRoamingForBrokenMobileSemantics should ideally be called before peers are created,
// though it will try to deal with it, and race maybe, if called after.
func (device *Device) DisableSomeRoamingForBrokenMobileSemantics() {
	device.net.brokenRoaming = true
	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.endpoints.Lock()
		peer.endpoints.disableRoaming = len(peer.endpoints.val) != 0
		peer.endpoints.Unlock()
	}
	device.peers.RUnlock()
}
