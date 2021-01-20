/*
Copyright © 2020 Bob Callaway <bcallawa@redhat.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package rekordpromise

import (
	"errors"
	"fmt"
	"sync"

	"github.com/blang/semver"

	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types"

	"github.com/go-openapi/swag"
	"github.com/projectrekor/rekor/pkg/generated/models"
)

const (
	KIND = "rekordPromise"
)

type BaseRekordPromiseType struct{}

func (rt BaseRekordPromiseType) Kind() string {
	return KIND
}

func init() {
	types.TypeMap.Set(KIND, New)
}

func New() types.TypeImpl {
	return &BaseRekordPromiseType{}
}

type VersionFactory func() types.EntryImpl

type versionFactoryMap struct {
	versionFactories map[string]VersionFactory

	sync.RWMutex
}

func (vfm *versionFactoryMap) Get(version string) (VersionFactory, bool) {
	vfm.RLock()
	defer vfm.RUnlock()

	semverToMatch, err := semver.Parse(version)
	if err != nil {
		log.Logger.Error(err)
		return nil, false
	}

	//will return first function that matches
	for k, v := range vfm.versionFactories {
		semverRange, err := semver.ParseRange(k)
		if err != nil {
			log.Logger.Error(err)
			return nil, false
		}

		if semverRange(semverToMatch) {
			return v, true
		}
	}
	return nil, false
}

func (vfm *versionFactoryMap) Set(constraint string, vf VersionFactory) {
	vfm.Lock()
	defer vfm.Unlock()

	if _, err := semver.ParseRange(constraint); err != nil {
		log.Logger.Error(err)
		return
	}

	vfm.versionFactories[constraint] = vf
}

var SemVerToFacFnMap = &versionFactoryMap{versionFactories: make(map[string]VersionFactory)}

func (rt BaseRekordPromiseType) UnmarshalEntry(pe models.ProposedEntry) (types.EntryImpl, error) {
	rp, ok := pe.(*models.RekordPromise)
	if !ok {
		return nil, errors.New("cannot unmarshal non-RekordPromise types")
	}

	if genFn, found := SemVerToFacFnMap.Get(swag.StringValue(rp.APIVersion)); found {
		entry := genFn()
		if entry == nil {
			return nil, fmt.Errorf("failure generating RekordPromise object for version '%v'", rp.APIVersion)
		}
		if err := entry.Unmarshal(rp); err != nil {
			return nil, err
		}
		return entry, nil
	}
	return nil, fmt.Errorf("RekordPromiseType implementation for version '%v' not found", swag.StringValue(rp.APIVersion))
}
