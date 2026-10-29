// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
// Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package gost3410

import (
	"errors"
	"math/big"
)

func (prv *PrivateKey) KEK(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	if prv == nil || prv.C == nil || prv.C.Q == nil || prv.Key == nil || pub == nil ||
		prv.Key.Sign() <= 0 || prv.Key.Cmp(prv.C.Q) >= 0 {
		return nil, errors.New("gost3410: invalid VKO key pair")
	}
	priv := prv.Key.FillBytes(make([]byte, prv.C.PointSize()))
	return prv.C.KEK(priv, pub.X, pub.Y, ukm)
}
