package ui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type actionMsg struct {
	details []string
	err     error
}

type model struct {
	title   string
	details []string
	err     error
	done    bool
	action  func(context.Context) ([]string, error)
}

func (m model) Init() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		details, err := m.action(ctx)
		return actionMsg{details: details, err: err}
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case actionMsg:
		m.details = msg.details
		m.err = msg.err
		m.done = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) View() string {
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("63")).Render(m.title)
	if !m.done {
		return fmt.Sprintf("%s\n\nRunning...\n", title)
	}
	if m.err != nil {
		err := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Render("FAILED")
		out := fmt.Sprintf("%s\n%s: %v\n", title, err, m.err)
		for _, d := range m.details {
			out += "- " + d + "\n"
		}
		return out
	}
	ok := lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Render("OK")
	out := fmt.Sprintf("%s\n%s\n", title, ok)
	for _, d := range m.details {
		out += "- " + d + "\n"
	}
	return out
}

func Run(title string, action func(context.Context) ([]string, error)) ([]string, error) {
	m := model{title: title, action: action}
	p := tea.NewProgram(m)
	final, err := p.Run()
	if err != nil {
		return nil, err
	}
	res := final.(model)
	return res.details, res.err
}
