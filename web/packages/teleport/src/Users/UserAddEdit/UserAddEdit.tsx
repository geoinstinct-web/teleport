/**
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import React, { useEffect, Dispatch, SetStateAction } from 'react';
import {
  ButtonPrimary,
  ButtonSecondary,
  Alert,
  Box,
  Flex,
  Text,
  ButtonIcon,
} from 'design';
import { ButtonTextWithAddIcon } from 'shared/components/ButtonTextWithAddIcon';
import * as Icons from 'design/Icon';
import Dialog, {
  DialogHeader,
  DialogTitle,
  DialogContent,
  DialogFooter,
} from 'design/Dialog';
import Validation from 'shared/components/Validation';
import FieldInput from 'shared/components/FieldInput';
import {
  FieldSelectAsync,
  FieldSelectCreatable,
} from 'shared/components/FieldSelect';
import { Option } from 'shared/components/Select';
import { requiredField, requiredAll } from 'shared/components/Validation/rules';

import { AllUserTraits } from 'teleport/services/user';

import UserTokenLink from './../UserTokenLink';
import useDialog, { Props } from './useDialog';

import type { TraitEditor } from './useDialog';

export default function Container(props: Props) {
  const dialog = useDialog(props);
  return <UserAddEdit {...dialog} />;
}

export function UserAddEdit(props: ReturnType<typeof useDialog>) {
  const {
    onChangeName,
    onChangeRoles,
    onClose,
    fetchRoles,
    setConfiguredTraits,
    allTraits,
    attempt,
    name,
    selectedRoles,
    onSave,
    isNew,
    token,
    configuredTraits,
  } = props;

  if (attempt.status === 'success' && isNew) {
    return <UserTokenLink onClose={onClose} token={token} asInvite={true} />;
  }

  function save(validator) {
    if (!validator.validate()) {
      return;
    }

    console.log('returning without save');
    return;
    onSave();
  }

  return (
    <Validation>
      {({ validator }) => (
        <Dialog
          dialogCss={() => ({
            maxWidth: '700px',
            width: '100%',
            height: '70%',
          })}
          disableEscapeKeyDown={false}
          onClose={onClose}
          open={true}
        >
          <DialogHeader>
            <DialogTitle>{isNew ? 'Create User' : 'Edit User'}</DialogTitle>
          </DialogHeader>
          <DialogContent>
            {attempt.status === 'failed' && (
              <Alert kind="danger" children={attempt.statusText} />
            )}
            <FieldInput
              label="Username"
              rule={requiredField('Username is required')}
              placeholder="Username"
              autoFocus
              value={name}
              onChange={e => onChangeName(e.target.value)}
              readonly={isNew ? false : true}
            />
            <FieldSelectAsync
              menuPosition="fixed"
              label="User Roles"
              rule={requiredField('At least one role is required')}
              placeholder="Click to select roles"
              isSearchable
              isMulti
              isSimpleValue
              isClearable={false}
              value={selectedRoles}
              onChange={values => onChangeRoles(values as Option[])}
              noOptionsMessage={() => 'No roles found'}
              loadOptions={async input => {
                const roles = await fetchRoles(input);
                return roles.map(r => ({ value: r, label: r }));
              }}
              elevated={true}
            />
            <TraitsEditor
              allTraits={allTraits}
              configuredTraits={configuredTraits}
              setConfiguredTraits={setConfiguredTraits}
            />
          </DialogContent>
          <DialogFooter>
            <ButtonPrimary
              mr="3"
              disabled={attempt.status === 'processing'}
              onClick={() => save(validator)}
            >
              Save
            </ButtonPrimary>
            <ButtonSecondary
              disabled={attempt.status === 'processing'}
              onClick={onClose}
            >
              Cancel
            </ButtonSecondary>
          </DialogFooter>
        </Dialog>
      )}
    </Validation>
  );
}

export type TraitEditorProps = {
  allTraits: AllUserTraits;
  setConfiguredTraits: Dispatch<SetStateAction<TraitEditor[]>>;
  configuredTraits: TraitEditor[];
};

function TraitsEditor({
  allTraits,
  configuredTraits,
  setConfiguredTraits,
}: TraitEditorProps) {
  const availableTraitNames = [
    'aws_role_arns',
    'azure_identities',
    'db_names',
    'db_roles',
    'db_users',
    'gcp_service_accounts',
    'host_user_gid',
    'host_user_uid',
    'kubernetes_groups',
    'kubernetes_users',
    'logins',
    'windows_logins',
  ];

  useEffect(() => {
    let newTrait = [];
    for (let trait in allTraits) {
      if (!allTraits[trait][0]) {
        continue;
      }
      if (allTraits[trait].length > 0) {
        newTrait.push({
          trait: { value: trait, label: trait },
          traitValues: allTraits[trait].map(t => ({
            value: t,
            label: t,
          })),
        });
      }
    }

    setConfiguredTraits(newTrait);
  }, [allTraits]);

  type InputOption = {
    labelField: 'trait' | 'traitValues';
    option: Option | Option[];
    index: number;
  };

  function handleInputChange(i: InputOption) {
    // validator.reset()
    const newTraits = [...configuredTraits];
    if (i.labelField === 'traitValues') {
      let traitValue: Option[] = i.option as Option[];

      newTraits[i.index] = {
        ...newTraits[i.index],
        [i.labelField]: [...traitValue],
      };
      setConfiguredTraits(newTraits);
    } else {
      let traitName: Option = i.option as Option;

      newTraits[i.index] = {
        ...newTraits[i.index],
        [i.labelField]: traitName,
      };
      setConfiguredTraits(newTraits);
    }
  }

  function addTrait() {
    const newTraits = [...configuredTraits];
    newTraits.push({
      trait: { value: '', label: 'Select or type new trait name and enter' },
      traitValues: [],
    });
    setConfiguredTraits(newTraits);
  }

  function removeTrait(index: number) {
    const newTraits = [...configuredTraits];
    newTraits.splice(index, 1);
    setConfiguredTraits(newTraits);
  }

  const addLabelText =
    configuredTraits.length > 0 ? 'Add another user trait' : 'Add user trait';

  const requireNoDuplicateTraits = (enteredTrait: Option) => () => {
    let k = configuredTraits.map(trait => trait.trait.value.toLowerCase());
    let occurance = 0;
    for (let t in k) {
      if (k[t] === enteredTrait.value.toLowerCase()) {
        occurance++;
      }
    }
    if (occurance > 1) {
      return { valid: false, message: 'Trait key should be unique for a user' };
    }
    return { valid: true };
  };

  return (
    <Box>
      {configuredTraits.length > 0 && <Text>Traits</Text>}

      <Box>
        {configuredTraits.map(({ trait, traitValues }, index) => {
          return (
            <Box mb={-5} key={index}>
              <Flex alignItems="start" mt={-3} justify="start">
                <Box width="290px" mr={1} mt={4}>
                  <FieldSelectCreatable
                    options={availableTraitNames.map(r => ({
                      value: r,
                      label: r,
                    }))}
                    placeholder="Select or type new trait name"
                    autoFocus
                    isSearchable
                    value={trait}
                    label="Trait Name"
                    rule={requiredAll(
                      requiredField('Trait key is required'),
                      requireNoDuplicateTraits
                    )}
                    onChange={e => {
                      handleInputChange({
                        option: e as Option,
                        labelField: 'trait',
                        index: index,
                      });
                    }}
                  />
                </Box>
                <Box width="400px" ml={3}>
                  <FieldSelectCreatable
                    mt={4}
                    ariaLabel="trait values"
                    css={`
                      background: ${props => props.theme.colors.levels.surface};
                    `}
                    placeholder="Type a new trait value and enter"
                    defaultValue={traitValues.map(r => ({
                      value: r,
                      label: r,
                    }))}
                    label="Trait Value"
                    isMulti
                    isSearchable
                    isClearable={false}
                    value={traitValues}
                    rule={requiredField('Trait value cannot be empty')}
                    onChange={e => {
                      handleInputChange({
                        option: e as Option,
                        labelField: 'traitValues',
                        index: index,
                      });
                    }}
                    isDisabled={false}
                    createOptionPosition="last"
                  />
                </Box>
                <ButtonIcon
                  ml={1}
                  mt={7}
                  size={1}
                  title="Remove Trait"
                  onClick={() => removeTrait(index)}
                  css={`
                    &:disabled {
                      opacity: 0.65;
                      pointer-events: none;
                    }
                  `}
                  disabled={false}
                >
                  <Icons.Trash size="medium" />
                </ButtonIcon>
              </Flex>
            </Box>
          );
        })}
      </Box>

      <Box mt={4}>
        <ButtonTextWithAddIcon
          onClick={addTrait}
          label={addLabelText}
          disabled={false}
        />
      </Box>
    </Box>
  );
}
