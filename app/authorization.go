// Copyright (c) 2016 Mattermost, Inc. All Rights Reserved.
// See License.txt for license information.

package app

import (
	l4g "github.com/alecthomas/log4go"
	"github.com/mattermost/platform/model"
)

func RequestHasPermissionTo(askingUserId string, vars map[string]string, permission *model.Permission) bool {

	// You always have permission to edit yourself
	if permission.Id == model.PERMISSION_EDIT_OTHER_USERS.Id && askingUserId == vars["user_id"] {
		return true
	}

	if permission.Level == model.PERMISSION_LEVEL_SYSTEM {
		return HasPermissionTo(askingUserId, permission)
	} else if permission.Level == model.PERMISSION_LEVEL_TEAM {
		return HasPermissionToTeam(askingUserId, vars["team_id"], permission)
	} else if permission.Level == model.PERMISSION_LEVEL_CHANNEL {
		return HasPermissionToChannel(askingUserId, vars["channel_id"], permission)
	}

	return false
}

func HasPermissionTo(askingUserId string, permission *model.Permission) bool {
	user, err := GetUser(askingUserId)
	if err != nil {
		return false
	}

	roles := user.GetRoles()

	return CheckIfRolesGrantPermission(roles, permission.Id)
}

func HasPermissionToTeam(askingUserId string, teamId string, permission *model.Permission) bool {
	if teamId == "" || askingUserId == "" {
		return false
	}

	teamMember, err := GetTeamMember(teamId, askingUserId)
	if err != nil {
		return false
	}

	roles := teamMember.GetRoles()

	if CheckIfRolesGrantPermission(roles, permission.Id) {
		return true
	}

	return HasPermissionTo(askingUserId, permission)
}

func HasPermissionToChannel(askingUserId string, channelId string, permission *model.Permission) bool {
	if channelId == "" || askingUserId == "" {
		return false
	}

	channelMember, err := GetChannelMember(channelId, askingUserId)
	if err != nil {
		return false
	}

	roles := channelMember.GetRoles()

	if CheckIfRolesGrantPermission(roles, permission.Id) {
		return true
	}

	var channel *model.Channel
	channel, err = GetChannel(channelId)
	if err != nil {
		return false
	}

	return HasPermissionToTeam(askingUserId, channel.TeamId, permission)
}

func HasPermissionToUser(askingUserId string, userId string) bool {
	if HasPermissionTo(askingUserId, model.PERMISSION_EDIT_OTHER_USERS) {
		return true
	}

	return false
}

func CheckIfRolesGrantPermission(roles []string, permissionId string) bool {
	for _, roleId := range roles {
		if role, ok := model.BuiltInRoles[roleId]; !ok {
			l4g.Debug("Bad role in system " + roleId)
			return false
		} else {
			permissions := role.Permissions
			for _, permission := range permissions {
				if permission == permissionId {
					return true
				}
			}
		}
	}

	return false
}
