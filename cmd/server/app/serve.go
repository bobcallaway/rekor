/*
Copyright © 2020 Luke Hinds <lhinds@redhat.com>

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

package app

import (
	"flag"

	"github.com/go-openapi/loads"
	"github.com/projectrekor/rekor/pkg/api"
	"github.com/projectrekor/rekor/pkg/generated/restapi/operations"
	"github.com/projectrekor/rekor/pkg/log"
	"github.com/projectrekor/rekor/pkg/types/rekord"
	rekord_v001 "github.com/projectrekor/rekor/pkg/types/rekord/v0.0.1"
	"github.com/projectrekor/rekor/pkg/types/rekordpromise"
	rekord_promise_v001 "github.com/projectrekor/rekor/pkg/types/rekordpromise/v0.0.1"

	"github.com/projectrekor/rekor/pkg/generated/restapi"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start http server with configured api",
	Long:  `Starts a http server and serves the configured api`,
	Run: func(cmd *cobra.Command, args []string) {

		// workaround for https://github.com/projectrekor/rekor/issues/68
		// from https://github.com/golang/glog/commit/fca8c8854093a154ff1eb580aae10276ad6b1b5f
		_ = flag.CommandLine.Parse([]string{})

		doc, _ := loads.Embedded(restapi.SwaggerJSON, restapi.FlatSwaggerJSON)
		server := restapi.NewServer(operations.NewRekorServerAPI(doc))
		defer func() {
			if err := server.Shutdown(); err != nil {
				log.Logger.Error(err)
			}
		}()

		//TODO: make this a config option for server to load via viper field
		//TODO: add command line option to print versions supported in binary

		// these trigger loading of package and therefore init() methods to run
		pluggableTypeMap := map[string]string{
			rekord.KIND:        rekord_v001.APIVERSION,
			rekordpromise.KIND: rekord_promise_v001.APIVERSION,
		}

		for k, v := range pluggableTypeMap {
			log.Logger.Infof("Loading support for pluggable type '%v'", k)
			log.Logger.Infof("Loading version '%v' for pluggable type '%v'", v, k)
		}

		server.Host = viper.GetString("rekor_server.address")
		server.Port = int(viper.GetUint("rekor_server.port"))
		server.EnabledListeners = []string{"http"}

		api.ConfigureAPI()
		server.ConfigureAPI()
		if err := server.Serve(); err != nil {
			log.Logger.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}
