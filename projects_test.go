//
// Copyright 2021, Sander van Harmelen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package gitlab

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestListProjects(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectsOptions{
		ListOptions: ListOptions{2, 3},
		Archived:    Bool(true),
		OrderBy:     String("name"),
		Sort:        String("asc"),
		Search:      String("query"),
		Simple:      Bool(true),
		Visibility:  Visibility(PublicVisibility),
	}

	projects, _, err := client.Projects.ListProjects(opt)
	if err != nil {
		t.Errorf("Projects.ListProjects returned error: %v", err)
	}

	want := []*Project{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListProjects returned %+v, want %+v", projects, want)
	}
}

func TestListUserProjects(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/users/1/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectsOptions{
		ListOptions: ListOptions{2, 3},
		Archived:    Bool(true),
		OrderBy:     String("name"),
		Sort:        String("asc"),
		Search:      String("query"),
		Simple:      Bool(true),
		Visibility:  Visibility(PublicVisibility),
	}

	projects, _, err := client.Projects.ListUserProjects(1, opt)
	if err != nil {
		t.Errorf("Projects.ListUserProjects returned error: %v", err)
	}

	want := []*Project{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListUserProjects returned %+v, want %+v", projects, want)
	}
}

func TestListProjectsUsersByID(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		testURL(t, r, "/api/v4/projects/1/users?page=2&per_page=3&search=query")
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectUserOptions{
		ListOptions: ListOptions{2, 3},
		Search:      String("query"),
	}

	projects, _, err := client.Projects.ListProjectsUsers(1, opt)
	if err != nil {
		t.Errorf("Projects.ListProjectsUsers returned error: %v", err)
	}

	want := []*ProjectUser{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListProjectsUsers returned %+v, want %+v", projects, want)
	}
}

func TestListProjectsUsersByName(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		testURL(t, r, "/api/v4/projects/namespace%2Fname/users?page=2&per_page=3&search=query")
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectUserOptions{
		ListOptions: ListOptions{2, 3},
		Search:      String("query"),
	}

	projects, _, err := client.Projects.ListProjectsUsers("namespace/name", opt)
	if err != nil {
		t.Errorf("Projects.ListProjectsUsers returned error: %v", err)
	}

	want := []*ProjectUser{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListProjectsUsers returned %+v, want %+v", projects, want)
	}
}

func TestListProjectsGroupsByID(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		testURL(t, r, "/api/v4/projects/1/groups?page=2&per_page=3&search=query")
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectGroupOptions{
		ListOptions: ListOptions{2, 3},
		Search:      String("query"),
	}

	groups, _, err := client.Projects.ListProjectsGroups(1, opt)
	if err != nil {
		t.Errorf("Projects.ListProjectsGroups returned error: %v", err)
	}

	want := []*ProjectGroup{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, groups) {
		t.Errorf("Projects.ListProjectsGroups returned %+v, want %+v", groups, want)
	}
}

func TestListProjectsGroupsByName(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		testURL(t, r, "/api/v4/projects/namespace%2Fname/groups?page=2&per_page=3&search=query")
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectGroupOptions{
		ListOptions: ListOptions{2, 3},
		Search:      String("query"),
	}

	groups, _, err := client.Projects.ListProjectsGroups("namespace/name", opt)
	if err != nil {
		t.Errorf("Projects.ListProjectsGroups returned error: %v", err)
	}

	want := []*ProjectGroup{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, groups) {
		t.Errorf("Projects.ListProjectsGroups returned %+v, want %+v", groups, want)
	}
}

func TestListOwnedProjects(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectsOptions{
		ListOptions: ListOptions{2, 3},
		Archived:    Bool(true),
		OrderBy:     String("name"),
		Sort:        String("asc"),
		Search:      String("query"),
		Simple:      Bool(true),
		Owned:       Bool(true),
		Visibility:  Visibility(PublicVisibility),
	}

	projects, _, err := client.Projects.ListProjects(opt)
	if err != nil {
		t.Errorf("Projects.ListOwnedProjects returned error: %v", err)
	}

	want := []*Project{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListOwnedProjects returned %+v, want %+v", projects, want)
	}
}

func TestListStarredProjects(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectsOptions{
		ListOptions: ListOptions{2, 3},
		Archived:    Bool(true),
		OrderBy:     String("name"),
		Sort:        String("asc"),
		Search:      String("query"),
		Simple:      Bool(true),
		Starred:     Bool(true),
		Visibility:  Visibility(PublicVisibility),
	}

	projects, _, err := client.Projects.ListProjects(opt)
	if err != nil {
		t.Errorf("Projects.ListStarredProjects returned error: %v", err)
	}

	want := []*Project{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListStarredProjects returned %+v, want %+v", projects, want)
	}
}

func TestGetProjectByID(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `{
			"id": 1,
			"container_registry_enabled": true,
			"container_expiration_policy": {
			  "cadence": "7d",
			  "enabled": false,
			  "keep_n": null,
			  "older_than": null,
			  "name_regex_delete": null,
			  "name_regex_keep": null,
			  "next_run_at": "2020-01-07T21:42:58.658Z"
			},
			"packages_enabled": false,
			"build_coverage_regex": "Total.*([0-9]{1,3})%"
		  }`)
	})

	wantTimestamp := time.Date(2020, 01, 07, 21, 42, 58, 658000000, time.UTC)
	want := &Project{
		ID:                       1,
		ContainerRegistryEnabled: true,
		ContainerExpirationPolicy: &ContainerExpirationPolicy{
			Cadence:   "7d",
			NextRunAt: &wantTimestamp,
		},
		PackagesEnabled:    false,
		BuildCoverageRegex: `Total.*([0-9]{1,3})%`,
	}

	project, _, err := client.Projects.GetProject(1, nil)
	if err != nil {
		t.Fatalf("Projects.GetProject returns an error: %v", err)
	}

	if !reflect.DeepEqual(want, project) {
		t.Errorf("Projects.GetProject returned %+v, want %+v", project, want)
	}
}

func TestGetProjectByName(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		testURL(t, r, "/api/v4/projects/namespace%2Fname")
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `{"id":1}`)
	})
	want := &Project{ID: 1}

	project, _, err := client.Projects.GetProject("namespace/name", nil)
	if err != nil {
		t.Fatalf("Projects.GetProject returns an error: %v", err)
	}

	if !reflect.DeepEqual(want, project) {
		t.Errorf("Projects.GetProject returned %+v, want %+v", project, want)
	}
}

func TestGetProjectWithOptions(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `{
			"id":1,
			"statistics": {
				"commit_count": 37,
				"storage_size": 1038090,
				"repository_size": 1038090,
				"lfs_objects_size": 0,
				"job_artifacts_size": 0
			}}`)
	})
	want := &Project{ID: 1, Statistics: &ProjectStatistics{
		CommitCount: 37,
		StorageStatistics: StorageStatistics{
			StorageSize:      1038090,
			RepositorySize:   1038090,
			LfsObjectsSize:   0,
			JobArtifactsSize: 0,
		},
	}}

	project, _, err := client.Projects.GetProject(1, &GetProjectOptions{Statistics: Bool(true)})
	if err != nil {
		t.Fatalf("Projects.GetProject returns an error: %v", err)
	}

	if !reflect.DeepEqual(want, project) {
		t.Errorf("Projects.GetProject returned %+v, want %+v", project, want)
	}
}

func TestCreateProject(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		fmt.Fprint(w, `{"id":1}`)
	})

	opt := &CreateProjectOptions{
		Name:        String("n"),
		MergeMethod: MergeMethod(RebaseMerge),
	}

	project, _, err := client.Projects.CreateProject(opt)
	if err != nil {
		t.Errorf("Projects.CreateProject returned error: %v", err)
	}

	want := &Project{ID: 1}
	if !reflect.DeepEqual(want, project) {
		t.Errorf("Projects.CreateProject returned %+v, want %+v", project, want)
	}
}

func TestUploadFile(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	tf, _ := ioutil.TempFile(os.TempDir(), "test")
	defer os.Remove(tf.Name())

	mux.HandleFunc("/api/v4/projects/1/uploads", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		if false == strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data;") {
			t.Fatalf("Projects.UploadFile request content-type %+v want multipart/form-data;", r.Header.Get("Content-Type"))
		}
		if r.ContentLength == -1 {
			t.Fatalf("Projects.UploadFile request content-length is -1")
		}
		fmt.Fprint(w, `{
		  "alt": "dk",
			"url": "/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.md",
			"markdown": "![dk](/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.png)"
		}`)
	})

	want := &ProjectFile{
		Alt:      "dk",
		URL:      "/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.md",
		Markdown: "![dk](/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.png)",
	}

	file, _, err := client.Projects.UploadFile(1, tf.Name())

	if err != nil {
		t.Fatalf("Projects.UploadFile returns an error: %v", err)
	}

	if !reflect.DeepEqual(want, file) {
		t.Errorf("Projects.UploadFile returned %+v, want %+v", file, want)
	}
}

func TestUploadFile_Retry(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	tf, _ := ioutil.TempFile(os.TempDir(), "test")
	defer os.Remove(tf.Name())

	isFirstRequest := true
	mux.HandleFunc("/api/v4/projects/1/uploads", func(w http.ResponseWriter, r *http.Request) {
		if isFirstRequest {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			isFirstRequest = false
			return
		}
		if false == strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data;") {
			t.Fatalf("Projects.UploadFile request content-type %+v want multipart/form-data;", r.Header.Get("Content-Type"))
		}
		if r.ContentLength == -1 {
			t.Fatalf("Projects.UploadFile request content-length is -1")
		}
		fmt.Fprint(w, `{
                  "alt": "dk",
                    "url": "/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.md",
                    "markdown": "![dk](/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.png)"
                }`)
	})

	want := &ProjectFile{
		Alt:      "dk",
		URL:      "/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.md",
		Markdown: "![dk](/uploads/66dbcd21ec5d24ed6ea225176098d52b/dk.png)",
	}

	file, _, err := client.Projects.UploadFile(1, tf.Name())

	if err != nil {
		t.Fatalf("Projects.UploadFile returns an error: %v", err)
	}

	if !reflect.DeepEqual(want, file) {
		t.Errorf("Projects.UploadFile returned %+v, want %+v", file, want)
	}
}

func TestListProjectForks(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/", func(w http.ResponseWriter, r *http.Request) {
		testURL(t, r, "/api/v4/projects/namespace%2Fname/forks?archived=true&order_by=name&page=2&per_page=3&search=query&simple=true&sort=asc&visibility=public")
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[{"id":1},{"id":2}]`)
	})

	opt := &ListProjectsOptions{}
	opt.ListOptions = ListOptions{2, 3}
	opt.Archived = Bool(true)
	opt.OrderBy = String("name")
	opt.Sort = String("asc")
	opt.Search = String("query")
	opt.Simple = Bool(true)
	opt.Visibility = Visibility(PublicVisibility)

	projects, _, err := client.Projects.ListProjectForks("namespace/name", opt)
	if err != nil {
		t.Errorf("Projects.ListProjectForks returned error: %v", err)
	}

	want := []*Project{{ID: 1}, {ID: 2}}
	if !reflect.DeepEqual(want, projects) {
		t.Errorf("Projects.ListProjects returned %+v, want %+v", projects, want)
	}
}

func TestShareProjectWithGroup(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/share", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
	})

	opt := &ShareWithGroupOptions{
		GroupID:     Int(1),
		GroupAccess: AccessLevel(AccessLevelValue(50)),
	}

	_, err := client.Projects.ShareProjectWithGroup(1, opt)
	if err != nil {
		t.Errorf("Projects.ShareProjectWithGroup returned error: %v", err)
	}
}

func TestDeleteSharedProjectFromGroup(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/share/2", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodDelete)
	})

	_, err := client.Projects.DeleteSharedProjectFromGroup(1, 2)
	if err != nil {
		t.Errorf("Projects.DeleteSharedProjectFromGroup returned error: %v", err)
	}
}

func TestGetApprovalConfiguration(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/approvals", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `{
			"approvers": [],
			"approver_groups": [],
			"approvals_before_merge": 3,
			"reset_approvals_on_push": false,
			"disable_overriding_approvers_per_merge_request": false,
			"merge_requests_author_approval": true,
			"merge_requests_disable_committers_approval": true,
			"require_password_to_approve": true
		}`)
	})

	approvals, _, err := client.Projects.GetApprovalConfiguration(1)
	if err != nil {
		t.Errorf("Projects.GetApprovalConfiguration returned error: %v", err)
	}

	want := &ProjectApprovals{
		Approvers:            []*MergeRequestApproverUser{},
		ApproverGroups:       []*MergeRequestApproverGroup{},
		ApprovalsBeforeMerge: 3,
		ResetApprovalsOnPush: false,
		DisableOverridingApproversPerMergeRequest: false,
		MergeRequestsAuthorApproval:               true,
		MergeRequestsDisableCommittersApproval:    true,
		RequirePasswordToApprove:                  true,
	}

	if !reflect.DeepEqual(want, approvals) {
		t.Errorf("Projects.GetApprovalConfiguration returned %+v, want %+v", approvals, want)
	}
}

func TestChangeApprovalConfiguration(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/approvals", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		testBody(t, r, `{"approvals_before_merge":3}`)
		fmt.Fprint(w, `{
			"approvers": [],
			"approver_groups": [],
			"approvals_before_merge": 3,
			"reset_approvals_on_push": false,
			"disable_overriding_approvers_per_merge_request": false,
			"merge_requests_author_approval": true,
			"merge_requests_disable_committers_approval": true,
			"require_password_to_approve": true
		}`)
	})

	opt := &ChangeApprovalConfigurationOptions{
		ApprovalsBeforeMerge: Int(3),
	}

	approvals, _, err := client.Projects.ChangeApprovalConfiguration(1, opt)
	if err != nil {
		t.Errorf("Projects.ChangeApprovalConfigurationOptions returned error: %v", err)
	}

	want := &ProjectApprovals{
		Approvers:            []*MergeRequestApproverUser{},
		ApproverGroups:       []*MergeRequestApproverGroup{},
		ApprovalsBeforeMerge: 3,
		ResetApprovalsOnPush: false,
		DisableOverridingApproversPerMergeRequest: false,
		MergeRequestsAuthorApproval:               true,
		MergeRequestsDisableCommittersApproval:    true,
		RequirePasswordToApprove:                  true,
	}

	if !reflect.DeepEqual(want, approvals) {
		t.Errorf("Projects.ChangeApprovalConfigurationOptions  returned %+v, want %+v", approvals, want)
	}
}

func TestChangeAllowedApprovers(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/approvers", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPut)
		testBody(t, r, `{"approver_group_ids":[1],"approver_ids":[2]}`)
		fmt.Fprint(w, `{
			"approver_groups": [{"group":{"id":1}}],
			"approvers": [{"user":{"id":2}}]
		}`)
	})

	opt := &ChangeAllowedApproversOptions{
		ApproverGroupIDs: []int{1},
		ApproverIDs:      []int{2},
	}

	approvals, _, err := client.Projects.ChangeAllowedApprovers(1, opt)
	if err != nil {
		t.Errorf("Projects.ChangeApproversConfigurationOptions returned error: %v", err)
	}

	want := &ProjectApprovals{
		ApproverGroups: []*MergeRequestApproverGroup{
			{
				Group: struct {
					ID                   int    `json:"id"`
					Name                 string `json:"name"`
					Path                 string `json:"path"`
					Description          string `json:"description"`
					Visibility           string `json:"visibility"`
					AvatarURL            string `json:"avatar_url"`
					WebURL               string `json:"web_url"`
					FullName             string `json:"full_name"`
					FullPath             string `json:"full_path"`
					LFSEnabled           bool   `json:"lfs_enabled"`
					RequestAccessEnabled bool   `json:"request_access_enabled"`
				}{
					ID: 1,
				},
			},
		},
		Approvers: []*MergeRequestApproverUser{
			{
				User: &BasicUser{
					ID: 2,
				},
			},
		},
	}

	if !reflect.DeepEqual(want, approvals) {
		t.Errorf("Projects.ChangeAllowedApprovers returned %+v, want %+v", approvals, want)
	}
}

func TestForkProject(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	namespace := "mynamespace"
	name := "myreponame"
	path := "myrepopath"

	mux.HandleFunc("/api/v4/projects/1/fork", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		testBody(t, r, fmt.Sprintf(`{"name":"%s","namespace":"%s","path":"%s"}`, name, namespace, path))
		fmt.Fprint(w, `{"id":2}`)
	})

	project, _, err := client.Projects.ForkProject(1, &ForkProjectOptions{
		Namespace: String(namespace),
		Name:      String(name),
		Path:      String(path),
	})
	if err != nil {
		t.Errorf("Projects.ForkProject returned error: %v", err)
	}

	want := &Project{ID: 2}
	if !reflect.DeepEqual(want, project) {
		t.Errorf("Projects.ForProject returned %+v, want %+v", project, want)
	}
}

func TestGetProjectApprovalRules(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/approval_rules", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodGet)
		fmt.Fprint(w, `[
			{
				"id": 1,
				"name": "security",
				"rule_type": "regular",
				"eligible_approvers": [
					{
						"id": 5,
						"name": "John Doe",
						"username": "jdoe",
						"state": "active",
						"avatar_url": "https://www.gravatar.com/avatar/0?s=80&d=identicon",
						"web_url": "http://localhost/jdoe"
					},
					{
						"id": 50,
						"name": "Group Member 1",
						"username": "group_member_1",
						"state": "active",
						"avatar_url": "https://www.gravatar.com/avatar/0?s=80&d=identicon",
						"web_url": "http://localhost/group_member_1"
					}
				],
				"approvals_required": 3,
				"users": [
					{
						"id": 5,
						"name": "John Doe",
						"username": "jdoe",
						"state": "active",
						"avatar_url": "https://www.gravatar.com/avatar/0?s=80&d=identicon",
						"web_url": "http://localhost/jdoe"
					}
				],
				"groups": [
					{
						"id": 5,
						"name": "group1",
						"path": "group1",
						"description": "",
						"visibility": "public",
						"lfs_enabled": false,
						"avatar_url": null,
						"web_url": "http://localhost/groups/group1",
						"request_access_enabled": false,
						"full_name": "group1",
						"full_path": "group1",
						"parent_id": null,
						"ldap_cn": null,
						"ldap_access": null
					}
				],
				"protected_branches": [
					  {
						"id": 1,
						"name": "master",
						"push_access_levels": [
						  {
							"access_level": 30,
							"access_level_description": "Developers + Maintainers"
						  }
						],
						"merge_access_levels": [
						  {
							"access_level": 30,
							"access_level_description": "Developers + Maintainers"
						  }
						],
						"unprotect_access_levels": [
						  {
							"access_level": 40,
							"access_level_description": "Maintainers"
						  }
						],
						"code_owner_approval_required": false
					  }
                ],
				"contains_hidden_groups": false
			}
		]`)
	})

	approvals, _, err := client.Projects.GetProjectApprovalRules(1)
	if err != nil {
		t.Errorf("Projects.GetProjectApprovalRules returned error: %v", err)
	}

	want := []*ProjectApprovalRule{
		{
			ID:       1,
			Name:     "security",
			RuleType: "regular",
			EligibleApprovers: []*BasicUser{
				{
					ID:        5,
					Name:      "John Doe",
					Username:  "jdoe",
					State:     "active",
					AvatarURL: "https://www.gravatar.com/avatar/0?s=80&d=identicon",
					WebURL:    "http://localhost/jdoe",
				},
				{
					ID:        50,
					Name:      "Group Member 1",
					Username:  "group_member_1",
					State:     "active",
					AvatarURL: "https://www.gravatar.com/avatar/0?s=80&d=identicon",
					WebURL:    "http://localhost/group_member_1",
				},
			},
			ApprovalsRequired: 3,
			Users: []*BasicUser{
				{
					ID:        5,
					Name:      "John Doe",
					Username:  "jdoe",
					State:     "active",
					AvatarURL: "https://www.gravatar.com/avatar/0?s=80&d=identicon",
					WebURL:    "http://localhost/jdoe",
				},
			},
			Groups: []*Group{
				{
					ID:                   5,
					Name:                 "group1",
					Path:                 "group1",
					Description:          "",
					Visibility:           PublicVisibility,
					LFSEnabled:           false,
					AvatarURL:            "",
					WebURL:               "http://localhost/groups/group1",
					RequestAccessEnabled: false,
					FullName:             "group1",
					FullPath:             "group1",
				},
			},
			ProtectedBranches: []*ProtectedBranch{
				{
					ID:   1,
					Name: "master",
					PushAccessLevels: []*BranchAccessDescription{
						{
							AccessLevel:            30,
							AccessLevelDescription: "Developers + Maintainers",
						},
					},
					MergeAccessLevels: []*BranchAccessDescription{
						{
							AccessLevel:            30,
							AccessLevelDescription: "Developers + Maintainers",
						},
					},
					UnprotectAccessLevels: []*BranchAccessDescription{
						{
							AccessLevel:            40,
							AccessLevelDescription: "Maintainers",
						},
					},
					AllowForcePush:            false,
					CodeOwnerApprovalRequired: false,
				},
			},
		},
	}

	if !reflect.DeepEqual(want, approvals) {
		t.Errorf("Projects.GetProjectApprovalRules returned %+v, want %+v", approvals, want)
	}
}

func TestCreateProjectApprovalRule(t *testing.T) {
	mux, server, client := setup(t)
	defer teardown(server)

	mux.HandleFunc("/api/v4/projects/1/approval_rules", func(w http.ResponseWriter, r *http.Request) {
		testMethod(t, r, http.MethodPost)
		fmt.Fprint(w, `{
			"id": 1,
			"name": "security",
			"rule_type": "regular",
			"eligible_approvers": [
				{
					"id": 5,
					"name": "John Doe",
					"username": "jdoe",
					"state": "active",
					"avatar_url": "https://www.gravatar.com/avatar/0?s=80&d=identicon",
					"web_url": "http://localhost/jdoe"
				},
				{
					"id": 50,
					"name": "Group Member 1",
					"username": "group_member_1",
					"state": "active",
					"avatar_url": "https://www.gravatar.com/avatar/0?s=80&d=identicon",
					"web_url": "http://localhost/group_member_1"
				}
			],
			"approvals_required": 3,
			"users": [
				{
					"id": 5,
					"name": "John Doe",
					"username": "jdoe",
					"state": "active",
					"avatar_url": "https://www.gravatar.com/avatar/0?s=80&d=identicon",
					"web_url": "http://localhost/jdoe"
				}
			],
			"groups": [
				{
					"id": 5,
					"name": "group1",
					"path": "group1",
					"description": "",
					"visibility": "public",
					"lfs_enabled": false,
					"avatar_url": null,
					"web_url": "http://localhost/groups/group1",
					"request_access_enabled": false,
					"full_name": "group1",
					"full_path": "group1",
					"parent_id": null,
					"ldap_cn": null,
					"ldap_access": null
				}
			],
			"protected_branches": [
				{
				  "id": 1,
				  "name": "master",
				  "push_access_levels": [
					{
					  "access_level": 30,
					  "access_level_description": "Developers + Maintainers"
					}
				  ],
				  "merge_access_levels": [
					{
					  "access_level": 30,
					  "access_level_description": "Developers + Maintainers"
					}
				  ],
				  "unprotect_access_levels": [
					{
					  "access_level": 40,
					  "access_level_description": "Maintainers"
					}
				  ],
				  "code_owner_approval_required": false
				}
			],
			"contains_hidden_groups": false
		}`)
	})

	opt := &CreateProjectLevelRuleOptions{
		Name:              String("security"),
		ApprovalsRequired: Int(3),
		UserIDs:           []int{5, 50},
		GroupIDs:          []int{5},
	}

	rule, _, err := client.Projects.CreateProjectApprovalRule(1, opt)
	if err != nil {
		t.Errorf("Projects.CreateProjectApprovalRule returned error: %v", err)
	}

	want := &ProjectApprovalRule{
		ID:       1,
		Name:     "security",
		RuleType: "regular",
		EligibleApprovers: []*BasicUser{
			{
				ID:        5,
				Name:      "John Doe",
				Username:  "jdoe",
				State:     "active",
				AvatarURL: "https://www.gravatar.com/avatar/0?s=80&d=identicon",
				WebURL:    "http://localhost/jdoe",
			},
			{
				ID:        50,
				Name:      "Group Member 1",
				Username:  "group_member_1",
				State:     "active",
				AvatarURL: "https://www.gravatar.com/avatar/0?s=80&d=identicon",
				WebURL:    "http://localhost/group_member_1",
			},
		},
		ApprovalsRequired: 3,
		Users: []*BasicUser{
			{
				ID:        5,
				Name:      "John Doe",
				Username:  "jdoe",
				State:     "active",
				AvatarURL: "https://www.gravatar.com/avatar/0?s=80&d=identicon",
				WebURL:    "http://localhost/jdoe",
			},
		},
		Groups: []*Group{
			{
				ID:                   5,
				Name:                 "group1",
				Path:                 "group1",
				Description:          "",
				Visibility:           PublicVisibility,
				LFSEnabled:           false,
				AvatarURL:            "",
				WebURL:               "http://localhost/groups/group1",
				RequestAccessEnabled: false,
				FullName:             "group1",
				FullPath:             "group1",
			},
		},
		ProtectedBranches: []*ProtectedBranch{
			{
				ID:   1,
				Name: "master",
				PushAccessLevels: []*BranchAccessDescription{
					{
						AccessLevel:            30,
						AccessLevelDescription: "Developers + Maintainers",
					},
				},
				MergeAccessLevels: []*BranchAccessDescription{
					{
						AccessLevel:            30,
						AccessLevelDescription: "Developers + Maintainers",
					},
				},
				UnprotectAccessLevels: []*BranchAccessDescription{
					{
						AccessLevel:            40,
						AccessLevelDescription: "Maintainers",
					},
				},
				AllowForcePush:            false,
				CodeOwnerApprovalRequired: false,
			},
		},
	}

	if !reflect.DeepEqual(want, rule) {
		t.Errorf("Projects.CreateProjectApprovalRule returned %+v, want %+v", rule, want)
	}
}
