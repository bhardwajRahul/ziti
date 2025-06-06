package main

import (
	"embed"
	_ "embed"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/fablab"
	"github.com/openziti/fablab/kernel/lib/actions"
	"github.com/openziti/fablab/kernel/lib/actions/component"
	"github.com/openziti/fablab/kernel/lib/actions/host"
	"github.com/openziti/fablab/kernel/lib/actions/semaphore"
	"github.com/openziti/fablab/kernel/lib/binding"
	"github.com/openziti/fablab/kernel/lib/parallel"
	"github.com/openziti/fablab/kernel/lib/runlevel/0_infrastructure/aws_ssh_key"
	"github.com/openziti/fablab/kernel/lib/runlevel/0_infrastructure/semaphore"
	"github.com/openziti/fablab/kernel/lib/runlevel/0_infrastructure/terraform"
	distribution "github.com/openziti/fablab/kernel/lib/runlevel/3_distribution"
	"github.com/openziti/fablab/kernel/lib/runlevel/3_distribution/rsync"
	awsSshKeyDispose "github.com/openziti/fablab/kernel/lib/runlevel/6_disposal/aws_ssh_key"
	"github.com/openziti/fablab/kernel/lib/runlevel/6_disposal/terraform"
	"github.com/openziti/fablab/kernel/model"
	"github.com/openziti/fablab/resources"
	"github.com/openziti/ziti/zititest/models/test_resources"
	"github.com/openziti/ziti/zititest/zitilab"
	zitilibActions "github.com/openziti/ziti/zititest/zitilab/actions"
	"github.com/openziti/ziti/zititest/zitilab/actions/edge"
	"github.com/openziti/ziti/zititest/zitilab/chaos"
	"github.com/openziti/ziti/zititest/zitilab/models"
	"os"
	"path"
	"time"
)

const TargetZitiVersion = ""

//go:embed configs
var configResource embed.FS

type scaleStrategy struct{}

func (self scaleStrategy) IsScaled(entity model.Entity) bool {
	if entity.GetType() == model.EntityTypeHost {
		return entity.GetScope().HasTag("router") || entity.GetScope().HasTag("host")
	}
	return entity.GetType() == model.EntityTypeComponent && entity.GetScope().HasTag("host")
}

func (self scaleStrategy) GetEntityCount(entity model.Entity) uint32 {
	if entity.GetType() == model.EntityTypeHost {
		if entity.GetScope().HasTag("router") {
			return 2
		}
		if entity.GetScope().HasTag("host") {
			h := entity.(*model.Host)
			if h.Region.Id == "us-east-1" {
				return 8
			}
			return 6
		}
	}
	if entity.GetType() == model.EntityTypeComponent {
		return 10
	}
	return 1
}

var m = &model.Model{
	Id: "circuit-test",
	Scope: model.Scope{
		Defaults: model.Variables{
			"environment": "circuit-scale-test",
			"credentials": model.Variables{
				"aws": model.Variables{
					"managed_key": true,
				},
				"ssh": model.Variables{
					"username": "ubuntu",
				},
				"edge": model.Variables{
					"username": "admin",
					"password": "admin",
				},
			},
			"metrics": model.Variables{
				"influxdb": model.Variables{
					"url": "http://localhost:8086",
					"db":  "ziti",
				},
			},
		},
	},
	StructureFactories: []model.Factory{
		model.FactoryFunc(func(m *model.Model) error {
			err := m.ForEachHost("component.ctrl", 1, func(host *model.Host) error {
				host.InstanceType = "c5.xlarge"
				return nil
			})

			if err != nil {
				return err
			}

			err = m.ForEachHost("component.router", 1, func(host *model.Host) error {
				host.InstanceType = "c5.xlarge"
				return nil
			})

			if err != nil {
				return err
			}

			return m.ForEachComponent(".host", 1, func(c *model.Component) error {
				c.Type.(*zitilab.ZitiTunnelType).Mode = zitilab.ZitiTunnelModeHost
				return nil
			})
		}),
		model.FactoryFunc(func(m *model.Model) error {
			if val, _ := m.GetBoolVariable("ha"); !val {
				for _, host := range m.SelectHosts("component.ha") {
					delete(host.Region.Hosts, host.Id)
				}
			}

			for _, c := range m.SelectComponents(".router") {
				c.Tags = append(c.Tags, "tunneler")
			}

			return nil
		}),
		model.NewScaleFactoryWithDefaultEntityFactory(&scaleStrategy{}),
	},
	Resources: model.Resources{
		resources.Configs:   resources.SubFolder(configResource, "configs"),
		resources.Binaries:  os.DirFS(path.Join(os.Getenv("GOPATH"), "bin")),
		resources.Terraform: test_resources.TerraformResources(),
	},
	Regions: model.Regions{
		"us-east-1": {
			Region: "us-east-1",
			Site:   "us-east-1a",
			Hosts: model.Hosts{
				"ctrl1": {
					Components: model.Components{
						"ctrl1": {
							Scope: model.Scope{Tags: model.Tags{"ctrl"}},
							Type: &zitilab.ControllerType{
								Version: TargetZitiVersion,
							},
						},
					},
				},
				"router-us-{{.ScaleIndex}}": {
					Scope: model.Scope{Tags: model.Tags{"router"}},
					Components: model.Components{
						"router-us-{{.Host.ScaleIndex}}": {
							Scope: model.Scope{Tags: model.Tags{"router"}},
							Type: &zitilab.RouterType{
								Version: TargetZitiVersion,
							},
						},
					},
				},
			},
		},
		"eu-west-2": {
			Region: "eu-west-2",
			Site:   "eu-west-2a",
			Hosts: model.Hosts{
				"ctrl2": {
					Components: model.Components{
						"ctrl2": {
							Scope: model.Scope{Tags: model.Tags{"ctrl", "ha"}},
							Type: &zitilab.ControllerType{
								Version: TargetZitiVersion,
							},
						},
					},
				},
				"router-eu-{{.ScaleIndex}}": {
					Scope: model.Scope{Tags: model.Tags{"router"}},
					Components: model.Components{
						"router-eu-{{.Host.ScaleIndex}}": {
							Scope: model.Scope{Tags: model.Tags{"router"}},
							Type: &zitilab.RouterType{
								Version: TargetZitiVersion,
							},
						},
					},
				},
			},
		},
		"ap-southeast-2": {
			Region: "ap-southeast-2",
			Site:   "ap-southeast-2a",
			Hosts: model.Hosts{
				"ctrl3": {
					Components: model.Components{
						"ctrl3": {
							Scope: model.Scope{Tags: model.Tags{"ctrl", "ha"}},
							Type: &zitilab.ControllerType{
								Version: TargetZitiVersion,
							},
						},
					},
				},
				"router-ap-{{.ScaleIndex}}": {
					Scope: model.Scope{Tags: model.Tags{"router", "scaled"}},
					Components: model.Components{
						"router-ap-{{.Host.ScaleIndex}}": {
							Scope: model.Scope{Tags: model.Tags{"router"}},
							Type: &zitilab.RouterType{
								Version: TargetZitiVersion,
							},
						},
					},
				},
			},
		},
	},

	Actions: model.ActionBinders{
		"bootstrap": model.ActionBinder(func(m *model.Model) model.Action {
			workflow := actions.Workflow()

			workflow.AddAction(component.StopInParallel("*", 300))
			workflow.AddAction(host.GroupExec("*", 25, "rm -f logs/* ctrl.db"))
			workflow.AddAction(host.GroupExec("component.ctrl", 5, "rm -rf ./fablab/ctrldata"))

			workflow.AddAction(component.Start(".ctrl"))

			workflow.AddAction(semaphore.Sleep(2 * time.Second))
			workflow.AddAction(edge.InitRaftController("#ctrl1"))

			workflow.AddAction(edge.ControllerAvailable("#ctrl1", 30*time.Second))
			workflow.AddAction(edge.Login("#ctrl1"))
			workflow.AddAction(edge.InitEdgeRouters(models.RouterTag, 25))

			workflow.AddAction(zitilibActions.Edge("create", "edge-router-policy", "all", "--edge-router-roles", "#all", "--identity-roles", "#all"))
			workflow.AddAction(zitilibActions.Edge("create", "service-edge-router-policy", "all", "--service-roles", "#all", "--edge-router-roles", "#all"))

			workflow.AddAction(model.ActionFunc(func(run model.Run) error {
				ctrls := &CtrlClients{}
				if err := ctrls.init(run, "#ctrl1"); err != nil {
					return err
				}

				var tasks []parallel.LabeledTask
				for range 100 {
					task := createNewService(ctrls.getCtrl("ctrl1"), nil)
					tasks = append(tasks, task)
				}
				return parallel.ExecuteLabeled(tasks, 2, nil)
			}))

			workflow.AddAction(model.ActionFunc(func(run model.Run) error {
				ctrls := &CtrlClients{}
				if err := ctrls.init(run, "#ctrl1"); err != nil {
					return err
				}

				var tasks []parallel.LabeledTask
				for range 100 {
					task := createNewIdentity(ctrls.getCtrl("ctrl1"))
					tasks = append(tasks, task)
				}
				return parallel.ExecuteLabeled(tasks, 2, nil)
			}))

			workflow.AddAction(model.ActionFunc(func(run model.Run) error {
				ctrls := &CtrlClients{}
				if err := ctrls.init(run, "#ctrl1"); err != nil {
					return err
				}

				var tasks []parallel.LabeledTask
				for range 100 {
					task := createNewServicePolicy(ctrls.getCtrl("ctrl1"))
					tasks = append(tasks, task)
				}
				return parallel.ExecuteLabeled(tasks, 2, nil)
			}))

			workflow.AddAction(semaphore.Sleep(2 * time.Second))
			workflow.AddAction(edge.RaftJoin("ctrl1", ".ctrl"))
			workflow.AddAction(semaphore.Sleep(5 * time.Second))

			workflow.AddAction(component.StartInParallel(".router", 10))
			workflow.AddAction(semaphore.Sleep(2 * time.Second))

			return workflow
		}),
		"stop": model.Bind(component.StopInParallelHostExclusive("*", 15)),
		"clean": model.Bind(actions.Workflow(
			component.StopInParallelHostExclusive("*", 15),
			host.GroupExec("*", 25, "rm -f logs/*"),
		)),
		"login":  model.Bind(edge.Login("#ctrl1")),
		"login2": model.Bind(edge.Login("#ctrl2")),
		"login3": model.Bind(edge.Login("#ctrl3")),
		"restart": model.ActionBinder(func(run *model.Model) model.Action {
			workflow := actions.Workflow()
			workflow.AddAction(component.StopInParallel("*", 100))
			workflow.AddAction(host.GroupExec("*", 25, "rm -f logs/*"))
			workflow.AddAction(component.Start(".ctrl"))
			workflow.AddAction(semaphore.Sleep(2 * time.Second))
			workflow.AddAction(component.StartInParallel(".router", 10))
			workflow.AddAction(semaphore.Sleep(2 * time.Second))
			workflow.AddAction(component.StartInParallel(".host", 50))
			return workflow
		}),
		"sowChaos": model.Bind(model.ActionFunc(sowChaos)),
		"validateUp": model.Bind(model.ActionFunc(func(run model.Run) error {
			if err := chaos.ValidateUp(run, ".ctrl", 3, 15*time.Second); err != nil {
				return err
			}
			err := run.GetModel().ForEachComponent(".ctrl", 3, func(c *model.Component) error {
				return edge.ControllerAvailable(c.Id, 30*time.Second).Execute(run)
			})
			if err != nil {
				return err
			}
			if err := chaos.ValidateUp(run, ".router", 100, time.Minute); err != nil {
				pfxlog.Logger().WithError(err).Error("validate up failed, trying to start all routers again")
				return component.StartInParallel(".router", 100).Execute(run)
			}
			return nil
		})),
		"validate": model.Bind(model.ActionFunc(validateRouterDataModel)),
		"testIteration": model.Bind(model.ActionFunc(func(run model.Run) error {
			return run.GetModel().Exec(run,
				"sowChaos",
				"validateUp",
				"validate",
			)
		})),
	},

	Infrastructure: model.Stages{
		aws_ssh_key.Express(),
		&terraform_0.Terraform{
			Retries: 3,
			ReadyCheck: &semaphore_0.ReadyStage{
				MaxWait: 90 * time.Second,
			},
		},
	},

	Distribution: model.Stages{
		distribution.DistributeSshKey("*"),
		rsync.RsyncStaged(),
	},

	Disposal: model.Stages{
		terraform.Dispose(),
		awsSshKeyDispose.Dispose(),
	},
}

func main() {
	m.AddActivationActions("stop", "bootstrap")

	model.AddBootstrapExtension(binding.AwsCredentialsLoader)
	model.AddBootstrapExtension(aws_ssh_key.KeyManager)

	fablab.InitModel(m)
	fablab.Run()
}
