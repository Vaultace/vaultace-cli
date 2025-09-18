/**
 * Team Command - Team collaboration and management
 */

const { Command } = require('commander')
const chalk = require('chalk')
const ora = require('ora')
const inquirer = require('inquirer')
const { table } = require('table')
const logger = require('../utils/logger')
const APIClient = require('../services/api-client')

const teamCommand = new Command('team')
  .description('👥 Team collaboration and management')

// List team members
teamCommand
  .command('list')
  .description('List team members')
  .option('--org <id>', 'organization ID')
  .option('--role <role>', 'filter by role (admin|member|viewer)')
  .action(async (options) => {
    const spinner = ora('Fetching team members...').start()

    try {
      logger.command('team list', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/collaboration/team', {
        params: {
          organization_id: options.org,
          role: options.role
        }
      })

      spinner.succeed('Team members retrieved')

      const members = response.data.members || []

      console.log(chalk.bold.blue('\n👥 Team Members\n'))

      if (members.length === 0) {
        console.log(chalk.gray('No team members found'))
        console.log(chalk.blue('Invite members with: vaultace team invite <email>'))
        return
      }

      const memberData = [
        ['Name', 'Email', 'Role', 'Status', 'Last Active']
      ]

      members.forEach(member => {
        memberData.push([
          member.name || 'N/A',
          member.email,
          member.role,
          member.status === 'active' ? '🟢 Active' : '🔴 Inactive',
          member.last_active || 'Never'
        ])
      })

      console.log(table(memberData))

      console.log(chalk.gray(`\nTotal: ${members.length} members`))

    } catch (error) {
      spinner.fail('Failed to fetch team members')
      logger.error('Team list error', { error: error.message })

      if (error.response?.status === 401) {
        console.log(chalk.yellow('\nAuthentication required. Run: vaultace auth login'))
      } else if (error.response?.status === 403) {
        console.log(chalk.red('\nInsufficient permissions. Admin access required.'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// Invite team member
teamCommand
  .command('invite')
  .description('Invite new team member')
  .argument('<email>', 'email address to invite')
  .option('--role <role>', 'member role (admin|member|viewer)', 'member')
  .option('--message <text>', 'custom invitation message')
  .action(async (email, options) => {
    try {
      logger.command('team invite', { email, role: options.role }, true)

      const { confirm } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'confirm',
          message: `Invite ${email} as ${options.role}?`,
          default: true
        }
      ])

      if (!confirm) {
        console.log(chalk.yellow('Invitation cancelled'))
        return
      }

      const spinner = ora('Sending invitation...').start()

      const apiClient = new APIClient()
      const response = await apiClient.post('/collaboration/invite', {
        email: email,
        role: options.role,
        message: options.message
      })

      spinner.succeed('Invitation sent successfully')

      console.log(chalk.green(`\n✅ Invitation sent to ${email}`))
      console.log(`Role: ${options.role}`)
      console.log(`Invitation ID: ${response.data.invitation_id}`)

    } catch (error) {
      if (error.spinner) {error.spinner.fail('Failed to send invitation')}
      logger.error('Team invite error', { error: error.message, email })

      if (error.response?.status === 409) {
        console.error(chalk.red('User is already a team member'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// Remove team member
teamCommand
  .command('remove')
  .description('Remove team member')
  .argument('<email>', 'email address to remove')
  .option('--force', 'skip confirmation prompt')
  .action(async (email, options) => {
    try {
      logger.command('team remove', { email }, true)

      if (!options.force) {
        const { confirm } = await inquirer.prompt([
          {
            type: 'confirm',
            name: 'confirm',
            message: `Remove ${email} from the team?`,
            default: false
          }
        ])

        if (!confirm) {
          console.log(chalk.yellow('Removal cancelled'))
          return
        }
      }

      const spinner = ora('Removing team member...').start()

      const apiClient = new APIClient()
      await apiClient.delete(`/collaboration/members/${encodeURIComponent(email)}`)

      spinner.succeed('Team member removed')

      console.log(chalk.green(`\n✅ ${email} removed from team`))

    } catch (error) {
      if (error.spinner) {error.spinner.fail('Failed to remove team member')}
      logger.error('Team remove error', { error: error.message, email })

      if (error.response?.status === 404) {
        console.error(chalk.red('Team member not found'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// Update member role
teamCommand
  .command('role')
  .description('Update team member role')
  .argument('<email>', 'team member email')
  .argument('<role>', 'new role (admin|member|viewer)')
  .action(async (email, role) => {
    try {
      logger.command('team role', { email, role }, true)

      const { confirm } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'confirm',
          message: `Change ${email} role to ${role}?`,
          default: true
        }
      ])

      if (!confirm) {
        console.log(chalk.yellow('Role change cancelled'))
        return
      }

      const spinner = ora('Updating role...').start()

      const apiClient = new APIClient()
      await apiClient.patch(`/collaboration/members/${encodeURIComponent(email)}`, {
        role: role
      })

      spinner.succeed('Role updated successfully')

      console.log(chalk.green(`\n✅ ${email} role updated to ${role}`))

    } catch (error) {
      if (error.spinner) {error.spinner.fail('Failed to update role')}
      logger.error('Team role error', { error: error.message, email, role })

      if (error.response?.status === 404) {
        console.error(chalk.red('Team member not found'))
      } else if (error.response?.status === 400) {
        console.error(chalk.red('Invalid role specified'))
      } else {
        console.error(chalk.red(`Error: ${error.message}`))
      }
      process.exit(1)
    }
  })

// Show team activity
teamCommand
  .command('activity')
  .description('Show recent team activity')
  .option('--limit <number>', 'number of activities to show', '10')
  .option('--user <email>', 'filter by user email')
  .action(async (options) => {
    const spinner = ora('Fetching team activity...').start()

    try {
      logger.command('team activity', options, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/collaboration/activity', {
        params: {
          limit: parseInt(options.limit),
          user: options.user
        }
      })

      spinner.succeed('Team activity retrieved')

      const activities = response.data.activities || []

      console.log(chalk.bold.green('\n📈 Team Activity\n'))

      if (activities.length === 0) {
        console.log(chalk.gray('No recent activity'))
        return
      }

      activities.forEach(activity => {
        const timestamp = new Date(activity.timestamp).toLocaleString()
        const icon = getActivityIcon(activity.type)
        console.log(`${icon} ${activity.user_name || activity.user_email} ${activity.description}`)
        console.log(chalk.gray(`   ${timestamp}\n`))
      })

    } catch (error) {
      spinner.fail('Failed to fetch team activity')
      logger.error('Team activity error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

// Show pending invitations
teamCommand
  .command('invitations')
  .description('Show pending team invitations')
  .action(async () => {
    const spinner = ora('Fetching pending invitations...').start()

    try {
      logger.command('team invitations', {}, true)

      const apiClient = new APIClient()
      const response = await apiClient.get('/collaboration/invitations')

      spinner.succeed('Invitations retrieved')

      const invitations = response.data.invitations || []

      console.log(chalk.bold.yellow('\n📧 Pending Invitations\n'))

      if (invitations.length === 0) {
        console.log(chalk.gray('No pending invitations'))
        return
      }

      const inviteData = [
        ['Email', 'Role', 'Sent', 'Expires']
      ]

      invitations.forEach(invite => {
        inviteData.push([
          invite.email,
          invite.role,
          new Date(invite.sent_at).toLocaleDateString(),
          new Date(invite.expires_at).toLocaleDateString()
        ])
      })

      console.log(table(inviteData))

      console.log(chalk.gray('To resend or cancel invitations, use the web dashboard.'))

    } catch (error) {
      spinner.fail('Failed to fetch invitations')
      logger.error('Team invitations error', { error: error.message })
      console.error(chalk.red(`Error: ${error.message}`))
      process.exit(1)
    }
  })

function getActivityIcon(type) {
  const icons = {
    'scan_completed': '🔍',
    'vulnerability_fixed': '🔧',
    'member_invited': '📧',
    'member_joined': '👋',
    'member_removed': '👋',
    'role_changed': '🔄',
    'repository_added': '📁',
    'repository_removed': '🗑️',
    'settings_changed': '⚙️',
    'default': '📝'
  }
  return icons[type] || icons.default
}

module.exports = teamCommand