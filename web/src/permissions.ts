import { useCallback } from 'react';
import { useFira } from './store';
import type { UUID } from './types';

// Project structure (the project itself, its tags, its tracks) is edited
// by the workspace owner and the project's leads/owners — the same rule
// as `has_project_lead_authority` / `require_project_lead` on the server,
// which is what actually enforces it. This only decides what to offer.
export function useCanEditProject(): (projectId: UUID) => boolean {
  const meId = useFira((s) => s.meId);
  const workspaceRole = useFira((s) => s.myWorkspaceRole);
  const projects = useFira((s) => s.projects);
  return useCallback(
    (projectId: UUID) => {
      if (workspaceRole === 'owner') return true;
      const role = projects.find((p) => p.id === projectId)?.members.find((m) => m.user_id === meId)?.role;
      return role === 'lead' || role === 'owner';
    },
    [meId, workspaceRole, projects],
  );
}
