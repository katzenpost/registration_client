// mailproxy.go - Katzenpost mailproxy configuration generator
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package mailproxy provides a library for generating mailproxy
// configuration and key material.
package mailproxy

import (
	"os"
	"fmt"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/utils"
	pConfig "github.com/katzenpost/mailproxy/config"
	vConfig "github.com/katzenpost/authority/voting/server/config"
	"golang.org/x/text/secure/precis"
)

const (
	mailproxyConfigName = "mailproxy.toml"
)

func makeConfig(providerKey *eddsa.PublicKey, authorityKey *eddsa.PublicKey, user, provider, authority, onionAuthority, dataDir, socksNet, socksAddr string, preferOnion bool, authorities []*vConfig.AuthorityPeer) *pConfig.Config {
	c := new(pConfig.Config)
	c.Proxy = new(pConfig.Proxy)
	c.Proxy.DataDir = dataDir
	//XXX: select between voting/nonvoting
	if len(authorities) == 0 {
		c.NonvotingAuthority = make(map[string]*pConfig.NonvotingAuthority)
		c.NonvotingAuthority["playground"] = &pConfig.NonvotingAuthority{}
		c.NonvotingAuthority["playground"].Address = authority
		c.NonvotingAuthority["playground"].PublicKey = authorityKey
		c.Account = make([]*pConfig.Account, 1)
		c.Account[0] = &pConfig.Account{User: user, Provider: provider,
			ProviderKeyPin: providerKey, InsecureKeyDiscovery: true,
			NonvotingAuthority: "playground"}
	} else {
		c.VotingAuthority = make(map[string]*pConfig.VotingAuthority)
		c.VotingAuthority["playground"] = &pConfig.VotingAuthority{}
		c.VotingAuthority["playground"].Peers = authorities
		c.Account = make([]*pConfig.Account, 1)
		c.Account[0] = &pConfig.Account{User: user, Provider: provider,
			ProviderKeyPin: providerKey, InsecureKeyDiscovery: true,
			VotingAuthority: "playground"}
	}
	c.FixupAndValidate() // apply defaulted entries
	if preferOnion {
		c.UpstreamProxy = &pConfig.UpstreamProxy{PreferedTransports: []pki.Transport{"onion",}, Type: "tor+socks5", Network: socksAddr, Address: onionAuthority}
	}
	return c
}

// GenerateConfig is used to generate mailproxy configuration
// files including key material in the specific dataDir directory.
// It returns the link layer authentication public key and the
// identity public key or an error upon failure. This function returns
// the public keys so that they may be used with the Provider
// account registration process.
func GenerateConfig(user, provider, providerKey, authority, onionAuthority, authorityKey, dataDir, socksNet, socksAddr string, preferOnion bool, authorities []*vConfig.AuthorityPeer) (*ecdh.PublicKey, *ecdh.PublicKey, error) {
	// Initialize the per-account directory.
	user, err := precis.UsernameCaseMapped.String(user)
	if err != nil {
		return nil, nil, err
	}
	provider, err = idna.Lookup.ToASCII(provider)
	if err != nil {
		return nil, nil, err
	}
	id := fmt.Sprintf("%s@%s", user, provider)
	basePath := filepath.Join(dataDir, id)
	if err := utils.MkDataDir(basePath); err != nil {
		return nil, nil, err
	}

	// generate and write keys to disk
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	linkPrivateKey, err := ecdh.Load(linkPriv, linkPub, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	idPriv := filepath.Join(basePath, "identity.private.pem")
	idPub := filepath.Join(basePath, "identity.public.pem")
	identityPrivateKey, err := ecdh.Load(idPriv, idPub, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// write the configuration file
	pk := new(eddsa.PublicKey)
	pk.FromString(providerKey)
	ak := new(eddsa.PublicKey)
	ak.FromString(authorityKey)
	cfg := makeConfig(pk, ak, user, provider, authority, onionAuthority, dataDir, socksNet, socksAddr, preferOnion, authorities)
	f, err := os.OpenFile(filepath.Join(dataDir, mailproxyConfigName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	enc := toml.NewEncoder(f)
	if err := enc.Encode(cfg); err != nil {
		return nil, nil, err
	}
	return linkPrivateKey.PublicKey(), identityPrivateKey.PublicKey(), nil
}
